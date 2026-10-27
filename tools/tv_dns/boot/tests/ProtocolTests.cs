using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;

class ProtocolTests {
    sealed class Server : IDisposable {
        public readonly TcpListener Listener = new TcpListener(IPAddress.Loopback, 0);
        public int Connections, Opens; public Exception Error;
        volatile bool stop;
        readonly Thread thread;
        public int Port { get { return ((IPEndPoint)Listener.LocalEndpoint).Port; } }
        public Server(Action<TcpClient,int,Server> handler) {
            Listener.Start();
            thread = new Thread(() => {
                try {
                    while (!stop) {
                        if (!Listener.Pending()) { Thread.Sleep(5); continue; }
                        using (var client = Listener.AcceptTcpClient()) {
                            Connections++;
                            handler(client, Connections, this);
                        }
                    }
                } catch (Exception e) { if (!stop) Error = e; }
            });
            thread.IsBackground = true; thread.Start();
        }
        public void Dispose() { stop = true; Listener.Stop(); thread.Join(2000); if (Error != null) throw Error; }
    }
    static void Check(bool ok, string why) { if (!ok) throw new Exception(why); }
    static void ClientHello(TcpClient c) { Check(SdbHandshake.Receive(c.GetStream()).Op == "CNXN", "Only CNXN may precede readiness"); }
    static void Hello(TcpClient c) { SdbHandshake.Send(c.GetStream(), "CNXN", 0x1000000, 4096, "device::mock::0\0"); }
    static void ResetThenReady() {
        using (var server = new Server((c,n,s) => {
            ClientHello(c);
            if (n < 3) { c.LingerState = new LingerOption(true,0); return; }
            Hello(c);
        })) {
            using (var c = SdbHandshake.ConnectReady(IPAddress.Loopback, server.Port, 2000, 200, 20, _ => {})) {
                Check(server.Connections == 3, "Readiness retries incorrect");
            }
        }
        Console.WriteLine("PASS two resets before readiness; no OPEN during retries");
    }
    static void NeverReady() {
        var watch = Stopwatch.StartNew();
        using (var server = new Server((c,n,s) => { ClientHello(c); SdbHandshake.Send(c.GetStream(), "AUTH", 0, 0, ""); })) {
            bool failed = false;
            try { using (SdbHandshake.ConnectReady(IPAddress.Loopback, server.Port, 350, 100, 20, _ => {})) {} }
            catch (TimeoutException) { failed = true; }
            Check(failed && server.Connections > 1 && watch.ElapsedMilliseconds < 1500, "Readiness deadline not bounded");
        }
        Console.WriteLine("PASS rejected handshakes exhaust bounded deadline");
    }
    static void LostOpenReply() {
        using (var server = new Server((c,n,s) => {
            ClientHello(c); Hello(c);
            Check(SdbHandshake.Receive(c.GetStream()).Op == "OPEN", "Expected one OPEN"); s.Opens++;
            c.LingerState = new LingerOption(true,0);
        })) {
            using (var c = SdbHandshake.ConnectReady(IPAddress.Loopback, server.Port, 1000, 200, 20, _ => {})) {
                bool failed = false;
                try { SdbHandshake.SubmitOnce(c, "shell:inert-mock"); } catch (IOException) { failed = true; }
                Check(failed, "Lost acknowledgement must remain uncertain");
            }
            Thread.Sleep(50);
            Check(server.Connections == 1 && server.Opens == 1, "OPEN was replayed");
        }
        Console.WriteLine("PASS disconnect after OPEN never reconnects/replays");
    }
    static void IncompletePacket() {
        using (var server = new Server((c,n,s) => { ClientHello(c); c.GetStream().WriteByte(0x43); Thread.Sleep(250); })) {
            var watch = Stopwatch.StartNew(); bool failed = false;
            try { using (SdbHandshake.ConnectReady(IPAddress.Loopback, server.Port, 300, 100, 20, _ => {})) {} }
            catch (TimeoutException) { failed = true; }
            Check(failed && watch.ElapsedMilliseconds < 1200, "Fragmented response escaped deadline");
        }
        Console.WriteLine("PASS partial header cannot hold readiness indefinitely");
    }
    static void SuccessfulOpen() {
        using (var server = new Server((c,n,s) => {
            ClientHello(c); Hello(c);
            Check(SdbHandshake.Receive(c.GetStream()).Op == "OPEN", "Expected OPEN"); s.Opens++;
            SdbHandshake.Send(c.GetStream(), "WRTE", 42, 1, "inert\n");
            Check(SdbHandshake.Receive(c.GetStream()).Op == "OKAY", "Missing output ACK");
            SdbHandshake.Send(c.GetStream(), "CLSE", 42, 1, "");
        })) {
            using (var c = SdbHandshake.ConnectReady(IPAddress.Loopback, server.Port, 1000, 200, 20, _ => {}))
                SdbHandshake.SubmitOnce(c, "shell:inert-mock");
            Check(server.Opens == 1 && server.Connections == 1, "Unexpected submissions");
        }
        Console.WriteLine("PASS WRTE/ACK/CLSE completes exactly one submission");
    }
    static void DetachedAck() {
        string path = Path.Combine(Path.GetTempPath(), "tv-dns-ack-" + Guid.NewGuid().ToString("N"));
        try {
            using (var p = Process.Start(new ProcessStartInfo("setsid", "/bin/sh") {UseShellExecute = false, RedirectStandardInput = true})) {
                p.StandardInput.WriteLine("exec </dev/null >/dev/null 2>&1; printf ack > '" + path + "'; sleep 1");
                p.StandardInput.Close();
                for (int i=0; i<20 && !File.Exists(path); i++) Thread.Sleep(50);
                Check(File.Exists(path) && File.ReadAllText(path)=="ack", "Detached shell ACK missing");
                Check(p.WaitForExit(2500), "Detached shell did not finish test");
            }
        } finally { if (File.Exists(path)) File.Delete(path); }
        Console.WriteLine("PASS detached watchdog receives source on stdin and acknowledges after FD closure");
    }
    static void Receipts() {
        string p = "boot_id=boot\nrequest_id=nonce\nuid=0(root)\ndns_ready=1\npayload done\n";
        Check(RootReceipt.Valid(p,"boot","nonce"),"Valid receipt rejected");
        Check(!RootReceipt.Valid(p,"oldboot","nonce"),"Old boot accepted");
        Check(!RootReceipt.Valid(p,"boot","oldnonce"),"Old request accepted");
        Check(!RootReceipt.Valid(p.Replace("dns_ready=1\n",""),"boot","nonce"),"Missing DNS readiness accepted");
        Check(!RootReceipt.Valid(p.Replace("payload done",""),"boot","nonce"),"Incomplete payload accepted");
        Console.WriteLine("PASS receipt binds current boot, request, root, DNS readiness and completion");
    }
    static void LogRotation() {
        string dir = Path.Combine(Path.GetTempPath(), "tv-dns-log-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try {
            string log = Path.Combine(dir, "probe.log");
            File.WriteAllText(log, new string('a', (int)BoundedLog.Limit + 1));
            File.WriteAllText(log + ".1", "older");
            BoundedLog.Append(log, "new");
            Check(File.ReadAllText(log) == "new\n", "Oversized log not rotated");
            Check(new FileInfo(log + ".1").Length == BoundedLog.Limit + 1, "Rotation did not replace the old copy");
            BoundedLog.Append(log, "next");
            Check(File.ReadAllText(log) == "new\nnext\n", "Small log rotated or lost lines");
            Check(Directory.GetFiles(dir).Length == 2, "More than one rotated copy kept");
        } finally { Directory.Delete(dir, true); }
        Console.WriteLine("PASS app log keeps one rotated copy beyond 64 KiB");
    }
    static int Main() {
        try { ResetThenReady(); NeverReady(); LostOpenReply(); IncompletePacket(); SuccessfulOpen(); DetachedAck(); Receipts(); LogRotation(); return 0; }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
    }
}
