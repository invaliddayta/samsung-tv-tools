// TV-local DNS supervisor with an optional domain-only blocklist. No firmware or resolver-setting writes.
// Runs in the transient tv-local-dns.service unit that startup.command creates.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public static class DnsPolicy {
    public const string Root = "/opt/var/tv-local-dns";
    public const string Group = "/sys/fs/cgroup/net_cls/tv-local-dns";
    public const string ClassId = "1413742594"; // 0x54440002, resolver ONLY
    public const string V4 = "TV_LOCAL_DNS4", V6 = "TV_LOCAL_DNS6";
    // Always keep the tested update-offer policy and its first-name health probe.
    public static readonly string[] Domains = {"osb-v2.samsungqbe.com", "osb.samsungqbe.com", "osbstg-v2.samsungqbe.com"};
    public const string Blocklist = Root + "/extra-domains.conf";
    public const int MaxBlocklistBytes = 65536, MaxExtraDomains = 256;
    static readonly string[] SharedParents = {"samsungqbe.com", "samsungcloudsolution.com", "samsungcloudsolution.net",
        "samsungcloud.tv", "samsungcloud.com", "samsungcloudcdn.com", "samsungosp.com", "samsung.com"};

    // Domain names only, not dnsmasq options, hosts files or adblock syntax. Validate the whole
    // file before applying any of it; limits bound memory, generated config and startup probes.
    public static string[] ParseDomains(string text) {
        if (text == null || Encoding.UTF8.GetByteCount(text) > MaxBlocklistBytes)
            throw new IOException("Blocklist exceeds 64 KiB");
        var names = new List<string>(Domains);
        var seen = new HashSet<string>(Domains, StringComparer.Ordinal);
        using (var reader = new StringReader(text)) {
            string line; int number = 0;
            while ((line = reader.ReadLine()) != null) {
                number++;
                int comment = line.IndexOf('#');
                string name = (comment < 0 ? line : line.Substring(0, comment)).Trim().ToLowerInvariant();
                if (name.Length == 0) continue;
                IPAddress address;
                bool valid = ValidName(name) && name.Contains(".") && !name.Contains("_") &&
                    !IPAddress.TryParse(name, out address);
                foreach (string label in name.Split('.'))
                    if (label.StartsWith("-") || label.EndsWith("-")) valid = false;
                foreach (string parent in SharedParents)
                    if (name == parent || parent.EndsWith("." + name, StringComparison.Ordinal)) valid = false;
                if (!valid) throw new IOException("Invalid or shared-parent domain on line " + number);
                if (seen.Add(name)) names.Add(name);
                if (names.Count > Domains.Length + MaxExtraDomains)
                    throw new IOException("Blocklist exceeds 256 extra domains");
            }
        }
        return names.ToArray();
    }
    public static string[] ReadDomains(string path) {
        if (new FileInfo(path).Length > MaxBlocklistBytes) throw new IOException("Blocklist exceeds 64 KiB");
        // Do not let StreamReader auto-detect UTF-16/32 and silently accept malformed input.
        string text = new UTF8Encoding(false, true).GetString(File.ReadAllBytes(path));
        if (text.StartsWith("\uFEFF", StringComparison.Ordinal)) text = text.Substring(1); // UTF-8 BOM
        return ParseDomains(text);
    }
    // `stat -c %F:%u:%g:%a:%s` without -L: reject symlinks, devices, pipes, other owners,
    // writable-by-others files and oversized input before opening the installed blocklist.
    public static bool SafeBlocklistMetadata(string text) {
        string[] f = text.Split(':'); long size;
        return f.Length == 5 && (f[0] == "regular file" || f[0] == "regular empty file") &&
            f[1] == "0" && f[2] == "0" && (f[3] == "600" || f[3] == "400") &&
            Int64.TryParse(f[4], NumberStyles.None, CultureInfo.InvariantCulture, out size) &&
            size >= 0 && size <= MaxBlocklistBytes;
    }
    public static readonly string[] Rules4 = {
        "-m cgroup --cgroup " + ClassId + " -j RETURN",
        "-p udp -m udp --dport 53 -j REDIRECT --to-ports 53",
        "-p tcp -m tcp --dport 53 -j REDIRECT --to-ports 53"
    };
    public static readonly string[] Rules6 = {
        "-d ::1/128 -j RETURN",
        "-m cgroup --cgroup " + ClassId + " -j RETURN",
        "-p udp -m udp --dport 53 -j REJECT --reject-with icmp6-port-unreachable",
        "-p tcp -m tcp --dport 53 -j REJECT --reject-with tcp-reset"
    };
    // Upstreams are AdGuard's filtering resolvers (the tested choice): they also drop ad and tracker names.
    // logQueries (opt-in, flag file Root/query-log): dnsmasq writes queries to stderr, without blocking DNS
    // when the reader is slow; the supervisor stores them in a bounded root-only log.
    public static string Config(bool logQueries = false, string[] domains = null) {
        var b = new StringBuilder("port=53\nlisten-address=127.0.0.1,127.0.0.2,::1\nbind-interfaces\nno-resolv\nno-hosts\nuser=nobody\ngroup=nobody\nserver=94.140.14.14\nserver=94.140.15.15\ncache-size=256\n");
        foreach (string domain in domains ?? Domains) b.Append("local=/" + domain + "/\n");
        if (logQueries) b.Append("log-queries\nlog-facility=-\nlog-async=100\n");
        b.Append("pid-file=" + Root + "/dnsmasq.pid\n");
        return b.ToString();
    }
    // Message of a dnsmasq query-log line ("dnsmasq[pid]: query[A] name from ..."), or null for
    // other output and for the supervisor's own health probe of Domains[0].
    public static string QueryLine(string line) {
        if (line == null || !line.StartsWith("dnsmasq")) return null;
        int start = line.IndexOf("]: ");
        if (start < 0) return null;
        string message = line.Substring(start + 3);
        string[] words = message.Split(' ');
        if (words.Length < 3 || words[1] == Domains[0]) return null;
        if (words[0].StartsWith("query[") || words[0] == "forwarded" || words[0] == "reply" ||
            words[0] == "cached" || words[0] == "cached-stale" || words[0] == "config") return message;
        return null;
    }
    // One DNS question with recursion desired. Shared by the health check and query mode.
    public static byte[] Query(int id, string name, int type) {
        if (!ValidName(name)) throw new ArgumentException("Invalid DNS name");
        using (var m = new MemoryStream()) {
            foreach (int n in new int[] {id, 0x0100, 1, 0, 0, 0}) Put16(m, n);
            foreach (string label in name.Split('.')) {
                byte[] b = Encoding.ASCII.GetBytes(label);
                m.WriteByte((byte)b.Length); m.Write(b, 0, b.Length);
            }
            m.WriteByte(0); Put16(m, type); Put16(m, 1);
            return m.ToArray();
        }
    }
    // Host name of 1-63 byte labels (letters, digits, '-' or '_'), at most 253 bytes in total.
    public static bool ValidName(string name) {
        if (name == null || name.Length == 0 || name.Length > 253) return false;
        foreach (string label in name.Split('.')) {
            if (label.Length == 0 || label.Length > 63) return false;
            foreach (char c in label)
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'))
                    return false;
        }
        return true;
    }
    static void Put16(Stream s, int n) { s.WriteByte((byte)(n >> 8)); s.WriteByte((byte)n); }
    static int Get16(byte[] b, int offset) { return (b[offset] << 8) | b[offset + 1]; }
    public static bool BlockedReply(byte[] data, int id) {
        if (data.Length < 12) return false;
        int ident = (data[0] << 8) | data[1], flags = (data[2] << 8) | data[3];
        return ident == id && (flags & 0x8000) != 0 && (flags & 0x200) == 0 &&
               (flags & 15) == 3 && data[4] == 0 && data[5] == 1 && data[6] == 0 && data[7] == 0;
    }
    // "rcode=N answers=M" for a response to query id, or null for anything else.
    public static string Outcome(byte[] reply, int id) {
        if (reply.Length < 12 || Get16(reply, 0) != id || (reply[2] & 0x80) == 0) return null;
        return "rcode=" + (reply[3] & 15) + " answers=" + Get16(reply, 6);
    }
    // A /proc/net/{tcp,udp}[6] row that occupies local port 53: any bound UDP socket, but only
    // a LISTEN (0A) TCP socket. TIME_WAIT rows left by a killed worker's TCP clients do not count.
    public static bool HoldsPort53(string line, bool tcp) {
        string[] f = line.Split((char[])null, StringSplitOptions.RemoveEmptyEntries);
        return f.Length > 1 && f[1].EndsWith(":0035") && (!tcp || (f.Length > 3 && f[3] == "0A"));
    }
}

// One DNS query and one reply. Every step is bounded; TCP shares one overall deadline.
public static class DnsClient {
    public static byte[] Exchange(IPAddress server, int port, bool tcp, byte[] query, int milliseconds) {
        return tcp ? OverTcp(server, port, query, milliseconds) : OverUdp(server, port, query, milliseconds);
    }
    static byte[] OverUdp(IPAddress server, int port, byte[] query, int milliseconds) {
        using (var c = new UdpClient(server.AddressFamily)) {
            c.Client.ReceiveTimeout = milliseconds; c.Client.SendTimeout = milliseconds; c.Connect(server, port);
            c.Send(query, query.Length); IPEndPoint from = null;
            return c.Receive(ref from);
        }
    }
    static byte[] OverTcp(IPAddress server, int port, byte[] query, int milliseconds) {
        var clock = Stopwatch.StartNew();
        using (var c = new TcpClient(server.AddressFamily)) {
            // As in the boot app's ConnectReady: no APM wait handle that a late socket callback could
            // find disposed. Disposing c cancels a timed-out connect; its late fault is observed.
            Task connect = c.ConnectAsync(server, port);
            connect.ContinueWith(t => { var observed = t.Exception; },
                TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);
            if (Task.WaitAny(new Task[] {connect}, Remaining(clock, milliseconds)) < 0) throw new TimeoutException("TCP connect timeout");
            connect.GetAwaiter().GetResult(); // A refused connect throws its own SocketException.
            var frame = new byte[query.Length + 2];
            frame[0] = (byte)(query.Length >> 8); frame[1] = (byte)query.Length;
            Array.Copy(query, 0, frame, 2, query.Length);
            using (NetworkStream s = c.GetStream()) {
                c.SendTimeout = Remaining(clock, milliseconds);
                s.Write(frame, 0, frame.Length);
                byte[] length = Exact(c, s, 2, clock, milliseconds);
                return Exact(c, s, (length[0] << 8) | length[1], clock, milliseconds);
            }
        }
    }
    static byte[] Exact(TcpClient c, NetworkStream s, int count, Stopwatch clock, int milliseconds) {
        var data = new byte[count];
        for (int pos = 0, n; pos < count; pos += n) {
            c.ReceiveTimeout = Remaining(clock, milliseconds);
            n = s.Read(data, pos, count - pos);
            if (n == 0) throw new IOException("DNS server closed the connection");
        }
        return data;
    }
    static int Remaining(Stopwatch clock, int milliseconds) {
        long left = milliseconds - clock.ElapsedMilliseconds;
        if (left <= 0) throw new TimeoutException("DNS deadline");
        return (int)left;
    }
}

class DnsSupervisor {
    [DllImport("libc")] static extern uint getuid();
    [DllImport("libc", SetLastError=true)] static extern int flock(int fd, int operation);
    [DllImport("libc", SetLastError=true)] static extern int rename(string from, string to);
    [DllImport("libc", SetLastError=true)] static extern int getpgid(int pid);
    [DllImport("libc", SetLastError=true)] static extern int kill(int pid, int signal);
    const string D = DnsPolicy.Root, CG = DnsPolicy.Group;
    static readonly object logLock = new object();
    static readonly Random random = new Random();
    static Process worker;
    static string boot;
    static int restarts;
    static bool queryLog, blocklistError;
    static string[] blockedDomains = DnsPolicy.Domains;
    const long QueryLogBytes = 4 << 20; // queries.log and queries.log.1: at most about 8 MiB
    static readonly Stopwatch runtime = Stopwatch.StartNew();
    static readonly Queue<long> failures = new Queue<long>();

    internal sealed class Result { public int Code; public string Text; public bool Truncated; }
    internal static Result Run(string executable, string arguments, bool required = true) {
        using (var p = new Process()) {
            p.StartInfo = new ProcessStartInfo(executable, arguments) {
                UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true
            };
            var output = new StringBuilder(); var gate = new object(); bool truncated = false;
            DataReceivedEventHandler collect = (sender, e) => {
                if (e.Data == null) return;
                lock (gate) { if (output.Length < 65536) output.AppendLine(e.Data); else truncated = true; }
            };
            p.OutputDataReceived += collect; p.ErrorDataReceived += collect;
            p.Start(); p.BeginOutputReadLine(); p.BeginErrorReadLine();
            if (!p.WaitForExit(8000)) {
                try { p.Kill(); p.WaitForExit(2000); } catch (InvalidOperationException) { }
                throw new TimeoutException("Command deadline: " + executable);
            }
            p.WaitForExit();
            Result result;
            lock (gate) result = new Result {Code = p.ExitCode, Text = output.ToString().Trim(), Truncated = truncated};
            if (required && result.Code != 0) throw new IOException(executable + " " + arguments + ": " + result.Text);
            return result;
        }
    }
    static void Log(string message) {
        lock (logLock) {
            string file = D + "/service.log";
            if (File.Exists(file) && new FileInfo(file).Length > 65536) {
                if (File.Exists(file + ".1")) File.Delete(file + ".1");
                File.Move(file, file + ".1");
            }
            File.AppendAllText(file, DateTime.UtcNow.ToString("o") + " " + message + "\n");
        }
    }
    static void LogQuery(string message) {
        lock (logLock) {
            string file = D + "/queries.log";
            if (File.Exists(file) && new FileInfo(file).Length > QueryLogBytes) {
                if (File.Exists(file + ".1")) File.Delete(file + ".1");
                File.Move(file, file + ".1");
            }
            File.AppendAllText(file, DateTime.UtcNow.ToString("o") + " " + message + "\n");
        }
    }
    static void State(bool ready) {
        string data = "{\"ready\":" + (ready ? "true" : "false") + ",\"boot_id\":\"" + boot +
            "\",\"supervisor_pid\":" + Process.GetCurrentProcess().Id + ",\"dns_pid\":" +
            ((worker != null && !worker.HasExited) ? worker.Id : 0) + ",\"restarts\":" + restarts +
            ",\"uptime\":" + File.ReadAllText("/proc/uptime").Split(' ')[0] + ",\"query_log\":" + (queryLog ? "true" : "false") +
            ",\"blocked_domains\":" + blockedDomains.Length + ",\"blocklist_error\":" + (blocklistError ? "true" : "false") + "}\n";
        File.WriteAllText(D + "/status.tmp", data);
        if (rename(D + "/status.tmp", D + "/status.json") != 0) throw new IOException("Atomic status write failed");
    }
    // Ownership markers hold the boot id. Chains and addresses do not survive a reboot, so a
    // marker from an earlier boot (or the old unscoped format) never claims a same-named one.
    static void Claim(string marker) { File.WriteAllText(marker, boot + "\n"); }
    internal static bool Claimed(string marker, string bootId) {
        return File.Exists(marker) && File.ReadAllText(marker).Trim() == bootId;
    }
    // One entry per IP family: firewall tool and table, the owned chain and its rules.
    sealed class Family {
        public readonly string Tool, Table, Chain;
        public readonly string[] Rules;
        public Family(string tool, string table, string chain, string[] rules) {
            Tool = tool; Table = table; Chain = chain; Rules = rules;
        }
        public string Marker { get { return D + "/" + Chain + ".owned"; } }
        public string Snapshot { get { return D + "/" + Chain + ".rules"; } }
        public Result Ipt(string arguments, bool required = true) { return Run(Tool, Table + " " + arguments, required); }
        // One required, complete listing of the whole table: present, absent or an exception.
        public bool Present() { return Defines(Ipt("-S"), Chain); }
        public bool Hooked() { return Ipt("-C OUTPUT -j " + Chain, false).Code == 0; }
        // Bounded unhook, then flush and delete. -X fails while any OUTPUT hook remains.
        public void Remove() {
            for (int i = 0; i < 16 && Hooked(); i++) Ipt("-D OUTPUT -j " + Chain);
            Ipt("-F " + Chain); Ipt("-X " + Chain);
        }
        public bool Owned() { return Claimed(Marker, boot); }
    }
    // Whether a successful, complete `-S` listing of a whole table (which always has the built-in
    // OUTPUT policy) defines chain. A failed, truncated or empty listing is no evidence of absence.
    internal static bool Defines(Result table, string chain) {
        string[] lines = table.Text.Split('\n');
        if (table.Code != 0 || table.Truncated || !Array.Exists(lines, line => line.Trim().StartsWith("-P OUTPUT ")))
            throw new IOException("Incomplete firewall table listing; state of " + chain + " unknown");
        return Array.Exists(lines, line => line.Trim() == "-N " + chain);
    }
    // Drop an ownership marker only once its chain is confirmed absent or deleted. An inspection
    // or removal failure propagates and keeps the marker, so the next start adopts the chain.
    internal static void Release(string marker, Func<bool> present, Action remove) {
        if (present()) remove();
        File.Delete(marker); // A later same-named chain is no longer ours.
    }
    static readonly Family[] Families = {
        new Family("/usr/sbin/iptables", "-w 5 -t nat", DnsPolicy.V4, DnsPolicy.Rules4),
        new Family("/usr/sbin/ip6tables", "-w 5", DnsPolicy.V6, DnsPolicy.Rules6)
    };
    static void PreflightOwnership() {
        foreach (Family f in Families)
            if (f.Present() && !f.Owned()) throw new IOException("Refusing existing unowned firewall chain " + f.Chain);
    }
    static void EnsureRules() {
        foreach (Family f in Families) {
            if (!f.Present()) {
                // Ownership is recorded before creating anything, so partial setup is cleanable.
                Claim(f.Marker);
                f.Ipt("-N " + f.Chain);
                foreach (string rule in f.Rules) f.Ipt("-A " + f.Chain + " " + rule);
                File.WriteAllText(f.Snapshot, f.Ipt("-S " + f.Chain).Text);
            } else if (!f.Owned() || !File.Exists(f.Snapshot) ||
                       File.ReadAllText(f.Snapshot) != f.Ipt("-S " + f.Chain).Text) {
                throw new IOException("Unexpected rules in " + f.Chain + "; refusing to overwrite");
            }
            if (!f.Hooked()) f.Ipt("-I OUTPUT 1 -j " + f.Chain);
        }
    }
    static void CleanupRules() {
        foreach (Family f in Families)
            if (f.Owned()) Release(f.Marker, f.Present, f.Remove);
    }
    static void EnsureLoopbackAddress() {
        // Do not rely on the broad 127/8 route being usable during early boot.
        // An explicit secondary address also prevents Samsung's DNS fallback.
        string addresses = Run("/usr/sbin/ip", "-o -4 address show dev lo").Text;
        if (addresses.Contains(" 127.0.0.2/")) return; // Never claim an existing address.
        Run("/usr/sbin/ip", "address add 127.0.0.2/32 dev lo");
        Claim(D + "/loopback-owned");
        if (!Run("/usr/sbin/ip", "-o -4 address show dev lo").Text.Contains(" 127.0.0.2/32 "))
            throw new IOException("Secondary loopback address not ready");
        Log("Created owned secondary loopback address");
    }
    static void CleanupLoopbackAddress() {
        string marker = D + "/loopback-owned";
        if (!Claimed(marker, boot)) return;
        if (Run("/usr/sbin/ip", "-o -4 address show dev lo").Text.Contains(" 127.0.0.2/32 "))
            Run("/usr/sbin/ip", "address del 127.0.0.2/32 dev lo");
        File.Delete(marker);
    }
    static bool PortInUse() {
        foreach (string file in new string[] {"tcp", "udp", "tcp6", "udp6"})
            foreach (string line in File.ReadAllLines("/proc/net/" + file))
                if (DnsPolicy.HoldsPort53(line, file.StartsWith("tcp"))) return true;
        return false;
    }
    static void VerifyWorker() {
        if (worker == null || worker.HasExited) throw new IOException("DNS worker exited");
        int pid = worker.Id;
        if (getpgid(pid) != pid) throw new IOException("DNS worker has no isolated process group");
        if (File.ReadAllText(D + "/dnsmasq.pid").Trim() != pid.ToString(CultureInfo.InvariantCulture))
            throw new IOException("Unexpected dnsmasq PID");
        // Reading another UID's /proc/PID/exe requires CAP_SYS_PTRACE once
        // dnsmasq drops privileges. Do not grant it just for diagnostics: we
        // created this fixed child and verify its parent/group/PID/credentials.
        if (!File.ReadAllText("/proc/" + pid + "/cgroup").Contains(":net_cls:/tv-local-dns\n"))
            throw new IOException("Worker outside resolver-only cgroup");
        if (!ControlledWorker(File.ReadAllText("/proc/" + pid + "/status"), Process.GetCurrentProcess().Id))
            throw new IOException("DNS child identity/privilege verification failed");
    }
    // From /proc/PID/status alone: dnsmasq under this supervisor, UID and GID 99 in all four
    // slots, empty inheritable/permitted/effective/ambient capability sets and no_new_privs.
    internal static bool ControlledWorker(string status, int parent) {
        var fields = new Dictionary<string, string>();
        foreach (string line in status.Split('\n')) {
            int colon = line.IndexOf(':');
            if (colon > 0) fields[line.Substring(0, colon)] = String.Join(" ",
                line.Substring(colon + 1).Split((char[])null, StringSplitOptions.RemoveEmptyEntries));
        }
        Func<string, string> get = key => fields.ContainsKey(key) ? fields[key] : "";
        foreach (string set in new string[] {"CapInh", "CapPrm", "CapEff", "CapAmb"})
            if (get(set).Length == 0 || get(set).TrimStart('0').Length != 0) return false;
        return get("Name") == "dnsmasq" && get("PPid") == parent.ToString(CultureInfo.InvariantCulture) &&
               get("Uid") == "99 99 99 99" && get("Gid") == "99 99 99 99" && get("NoNewPrivs") == "1";
    }
    static bool Probe(string domain, int type) {
        int id = random.Next(65536);
        byte[] query = DnsPolicy.Query(id, domain, type);
        try {
            return DnsPolicy.BlockedReply(DnsClient.Exchange(IPAddress.Loopback, 53, false, query, 1500), id);
        } catch (SocketException) { return false; }
    }
    static void StopWorker() {
        if (worker == null) return;
        try {
            // Include dnsmasq's TCP children, but never signal a broad process name.
            int group = worker.Id;
            if (Directory.Exists(CG)) {
                foreach (string task in File.ReadAllLines(CG + "/tasks")) {
                    int pid;
                    if (Int32.TryParse(task, out pid) && getpgid(pid) == group) {
                        kill(-group, 9); // Group was isolated and is still present in our dedicated cgroup.
                        break;
                    }
                }
            }
            if (!worker.HasExited) { worker.Kill(); worker.WaitForExit(3000); }
            // Killed tasks can stay listed briefly; StartWorker refuses a group that is not empty.
            if (Directory.Exists(CG)) Drained(CG + "/tasks", 3000);
        } finally { worker.Dispose(); worker = null; }
    }
    internal static bool Drained(string tasks, int milliseconds) {
        var clock = Stopwatch.StartNew();
        while (File.ReadAllText(tasks).Trim().Length != 0) {
            if (clock.ElapsedMilliseconds >= milliseconds) return false;
            Thread.Sleep(100);
        }
        return true;
    }
    static void StartWorker() {
        if (PortInUse()) throw new IOException("Port53 occupied; will not kill an unrelated resolver");
        if (File.Exists(D + "/dnsmasq.pid")) File.Delete(D + "/dnsmasq.pid");
        if (!Directory.Exists(CG)) Directory.CreateDirectory(CG);
        if (File.ReadAllText(CG + "/tasks").Trim().Length != 0) throw new IOException("Resolver cgroup is not empty");
        File.WriteAllText(CG + "/net_cls.classid", DnsPolicy.ClassId + "\n");
        if (File.ReadAllText(CG + "/net_cls.classid").Trim() != DnsPolicy.ClassId) throw new IOException("Cgroup class mismatch");
        queryLog = File.Exists(D + "/query-log");
        File.WriteAllText(D + "/dnsmasq.conf", DnsPolicy.Config(queryLog, blockedDomains));
        try { Run("/usr/bin/dnsmasq", "--test --conf-file=" + D + "/dnsmasq.conf"); }
        catch (IOException e) when (queryLog) {
            // An older dnsmasq without stderr logging must not cost DNS: run without the query log.
            Log("Query log unsupported, disabled: " + e.Message);
            queryLog = false;
            File.WriteAllText(D + "/dnsmasq.conf", DnsPolicy.Config(false, blockedDomains));
            Run("/usr/bin/dnsmasq", "--test --conf-file=" + D + "/dnsmasq.conf");
        }
        // Only the child joins the exempt net_cls cgroup; supervisor remains outside it.
        worker = new Process();
        worker.StartInfo = new ProcessStartInfo("/usr/bin/setsid", "/bin/sh") {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        bool logging = queryLog;
        DataReceivedEventHandler log = (sender,e) => {
            if (e.Data == null) return;
            if (!logging) { Log("dnsmasq: " + e.Data); return; }
            string query = DnsPolicy.QueryLine(e.Data);
            if (query != null) LogQuery(query);
            else if (e.Data.IndexOf("]: query[") < 0 && e.Data.IndexOf(" " + DnsPolicy.Domains[0] + " ") < 0) Log("dnsmasq: " + e.Data);
        };
        worker.OutputDataReceived += log; worker.ErrorDataReceived += log;
        worker.Start(); worker.BeginOutputReadLine(); worker.BeginErrorReadLine();
        worker.StandardInput.WriteLine("set -e; echo $$ > " + CG + "/tasks; exec /usr/bin/dnsmasq --keep-in-foreground --conf-file=" + D + "/dnsmasq.conf");
        worker.StandardInput.Close();
        for (int i = 0; i < 30 && !worker.HasExited; i++) {
            try { VerifyWorker(); break; } catch (IOException) { Thread.Sleep(100); }
        }
        VerifyWorker();
        foreach (string domain in blockedDomains)
            foreach (int type in new int[] {1,28})
                if (!Probe(domain,type)) throw new IOException("Local NXDOMAIN health check failed");
        Log("DNS worker ready pid=" + worker.Id + ", uid99, caps0");
    }
    static void StartOrRecover() {
        long now = runtime.ElapsedMilliseconds;
        while (failures.Count > 0 && now - failures.Peek() > 60000) failures.Dequeue();
        if (failures.Count >= 5) throw new IOException("Worker restart rate limit reached");
        failures.Enqueue(now);
        StopWorker(); StartWorker(); EnsureRules(); State(true);
    }
    // Single-instance lock shared by run and cleanup; throws `refusal` while another process
    // holds it. CoreCLR opens with its own shared flock, so contention can fail the open itself.
    internal static FileStream Lock(string path, string refusal) {
        FileStream locked;
        try { locked = new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite); }
        catch (IOException e) { throw new IOException(refusal + " (" + e.Message + ")", e); }
        if (flock(locked.SafeFileHandle.DangerousGetHandle().ToInt32(), 6) == 0) return locked; // LOCK_EX | LOCK_NB
        locked.Dispose();
        throw new IOException(refusal);
    }
    static void Cleanup() {
        // A live supervisor restores its chains, but never re-adds 127.0.0.2 once removed.
        using (Lock(D + "/supervisor.lock", "Supervisor is running; refusing cleanup")) {
            CleanupRules(); CleanupLoopbackAddress(); State(false);
        }
    }
    static void LoadBlocklist() {
        blockedDomains = DnsPolicy.Domains; blocklistError = false;
        if (!File.Exists(DnsPolicy.Blocklist)) return;
        try {
            Result metadata = Run("/usr/bin/stat", "-c %F:%u:%g:%a:%s -- " + DnsPolicy.Blocklist);
            if (metadata.Truncated || !DnsPolicy.SafeBlocklistMetadata(metadata.Text))
                throw new IOException("Blocklist must be a root:root regular file, mode 600 or 400, at most 64 KiB");
            blockedDomains = DnsPolicy.ReadDomains(DnsPolicy.Blocklist);
            Log("Loaded blocklist: " + blockedDomains.Length + " domains including the three defaults");
        } catch (Exception e) when (e is IOException || e is UnauthorizedAccessException ||
                                   e is ArgumentException || e is TimeoutException) {
            // A bad optional file must not take the TV's DNS away. Keep the core policy, report
            // the fallback, and never apply a partly parsed list. Reload requires a service restart.
            blocklistError = true;
            Log("Blocklist rejected; using three defaults: " + e.Message);
        }
    }
    static void Serve() {
        using (Lock(D + "/supervisor.lock", "Supervisor already running")) {
            LoadBlocklist();
            PreflightOwnership();
            State(false);
            try {
                EnsureLoopbackAddress();
                StartOrRecover();
                Log("IPv4 DNS redirect and IPv6 external-DNS rejection active");
                while (true) {
                    Thread.Sleep(5000);
                    if (worker.HasExited || !Probe(DnsPolicy.Domains[0],1)) {
                        State(false); restarts++; Log("Worker unhealthy; bounded restart=" + restarts);
                        StartOrRecover();
                    } else {
                        VerifyWorker(); EnsureRules(); State(true);
                    }
                }
            } finally { StopWorker(); CleanupRules(); CleanupLoopbackAddress(); State(false); }
        }
    }
    // Read-only diagnostic: `query IP udp|tcp NAME 1|28`. Needs no root and touches no
    // service state: no lock, log, status, firewall, cgroup or files under the service root.
    internal static int Query(string[] args, int port) {
        IPAddress server;
        if (args.Length != 5 || !ParseServer(args[1], out server) || (args[2] != "udp" && args[2] != "tcp") ||
            !DnsPolicy.ValidName(args[3]) || (args[4] != "1" && args[4] != "28")) {
            Console.Error.WriteLine("Usage: DnsSupervisor.dll query IP udp|tcp NAME 1|28");
            return 2;
        }
        int type = args[4] == "1" ? 1 : 28;
        try {
            int id = random.Next(65536);
            string outcome = DnsPolicy.Outcome(DnsClient.Exchange(server, port, args[2] == "tcp", DnsPolicy.Query(id, args[3], type), 3000), id);
            if (outcome == null) throw new IOException("Bad DNS response");
            Console.WriteLine("server={0} transport={1} name={2} type={3} {4}", server, args[2], args[3], type, outcome);
            return 0;
        } catch (Exception e) {
            Console.Error.WriteLine(e.GetType().Name + ": " + e.Message);
            return 1;
        }
    }
    // A literal address only: dotted-quad IPv4 as written, or IPv6 without an interface scope.
    static bool ParseServer(string text, out IPAddress server) {
        if (!IPAddress.TryParse(text, out server)) return false;
        return server.AddressFamily == AddressFamily.InterNetworkV6 ? server.ScopeId == 0 : server.ToString() == text;
    }
    // Offline/read-only validation; no root, lock, log, firewall or service changes.
    internal static int CheckBlocklist(string[] args) {
        if (args.Length != 2) { Console.Error.WriteLine("Usage: DnsSupervisor.dll check-blocklist FILE"); return 2; }
        try {
            string[] domains = DnsPolicy.ReadDomains(args[1]);
            Console.WriteLine("VALID blocked_domains={0} extra_domains={1}", domains.Length, domains.Length - DnsPolicy.Domains.Length);
            return 0;
        } catch (Exception e) when (e is IOException || e is UnauthorizedAccessException || e is ArgumentException) {
            Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 1;
        }
    }
    internal static int Main(string[] args) {
        if (args.Length > 0 && args[0] == "query") return Query(args, 53);
        if (args.Length > 0 && args[0] == "check-blocklist") return CheckBlocklist(args);
        try {
            if (getuid() != 0 || !Directory.Exists(D)) throw new IOException("Root-owned installation required");
            boot = File.ReadAllText("/proc/sys/kernel/random/boot_id").Trim();
            if (args.Length != 1) throw new ArgumentException("run or cleanup required");
            if (args[0] == "cleanup") { Cleanup(); return 0; }
            if (args[0] != "run") throw new ArgumentException("Unknown mode");
            Serve(); return 0;
        } catch (Exception e) {
            try { Log("ERROR " + e); } catch (Exception) { }
            Console.Error.WriteLine(e); return 1;
        }
    }
}
