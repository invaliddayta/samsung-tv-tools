using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
class PolicyTests {
    static void Check(bool ok, string why) { if (!ok) throw new Exception(why); }
    static void Policy() {
        string c = DnsPolicy.Config();
        Check(c.Contains("listen-address=127.0.0.1,127.0.0.2,::1\n") && c.Contains("bind-interfaces\n"), "Loopback binding");
        Check(c.Contains("no-resolv\n") && c.Contains("no-hosts\n") && !c.Contains("log-queries"), "No inherited/proxy resolver or query log");
        Check(DnsPolicy.Domains.Length == 3 && c.Split(new string[] {"local=/"}, StringSplitOptions.None).Length == 4, "Default remains three update-offer domains");
        string[] example = DnsPolicy.ReadDomains("extra-domains.conf.example");
        Check(example.Length == 25, "Example adds 22 optional domains");
        string expanded = DnsPolicy.Config(false, example);
        var seen = new System.Collections.Generic.HashSet<string>();
        foreach (string d in example)
            Check(DnsPolicy.ValidName(d) && d == d.ToLowerInvariant() && seen.Add(d) && expanded.Contains("local=/" + d + "/\n"), "Valid, unique block entry " + d);
        Check(DnsPolicy.Domains[0] == "osb-v2.samsungqbe.com", "Health probe name");
        string logged = DnsPolicy.Config(true);
        Check(logged == c.Replace("pid-file=", "log-queries\nlog-facility=-\nlog-async=100\npid-file="), "Opt-in query log only adds stderr logging");
        Check(DnsPolicy.QueryLine("dnsmasq[12]: query[A] lcprd1.samsungcloudsolution.net from 127.0.0.1") == "query[A] lcprd1.samsungcloudsolution.net from 127.0.0.1", "Query line");
        Check(DnsPolicy.QueryLine("dnsmasq[12]: reply example.com is 1.2.3.4") == "reply example.com is 1.2.3.4", "Reply line");
        Check(DnsPolicy.QueryLine("dnsmasq[12]: config samsungacr.com is NXDOMAIN") == "config samsungacr.com is NXDOMAIN", "Blocked line");
        Check(DnsPolicy.QueryLine("dnsmasq[12]: query[A] osb-v2.samsungqbe.com from 127.0.0.1") == null, "Health probe not logged");
        Check(DnsPolicy.QueryLine("dnsmasq[12]: started, version 2.80 cachesize 256") == null, "Status line not a query");
        Check(DnsPolicy.QueryLine("query[A] x.com from 127.0.0.1") == null && DnsPolicy.QueryLine(null) == null, "Foreign line");
        // Shared service domains must stay resolvable: clock, account, Smart Hub/app CDN, push.
        foreach (string keep in new string[] {"samsungqbe.com", "samsungcloudsolution.com", "samsungcloudsolution.net",
                 "samsungcloud.tv", "samsungcloud.com", "samsungcloudcdn.com", "samsungosp.com", "samsung.com", "gpm.samsungqbe.com",
                 "time.samsungcloudsolution.com", "time.samsungcloudsolution.net", "cdn.samsungcloudsolution.com"})
            Check(!seen.Contains(keep) && !expanded.Contains("local=/" + keep + "/"), "Shared service domain stays resolvable: " + keep);
        Check(!c.Contains("192.168.") && c.Contains("user=nobody\n"), "No private network dependence/root DNS");
        Check(DnsPolicy.Rules4.Length == 3 && DnsPolicy.Rules6.Length == 4, "Rule counts");
        Check(DnsPolicy.Rules4[0].Contains("-m cgroup") && !DnsPolicy.Rules4[0].Contains("uid"), "Resolver-only exemption");
        foreach (string rule in DnsPolicy.Rules4) Check(rule.Contains("RETURN") || rule.Contains("--dport 53"), "IPv4 scope");
        foreach (string rule in DnsPolicy.Rules6) Check(rule.Contains("RETURN") || rule.Contains("--dport 53"), "IPv6 scope");
    }
    static void Blocklists(string dir) {
        string[] names = DnsPolicy.ParseDomains("# comment\r\nEXAMPLE.com # inline\nexample.com\n\nosb.samsungqbe.com\n");
        Check(names.Length == 4 && names[0] == DnsPolicy.Domains[0] && names[3] == "example.com", "Normalize, deduplicate and retain defaults");
        Check(DnsPolicy.ParseDomains("").Length == 3, "Empty file retains defaults");
        foreach (string bad in new string[] {".", "com", "samsungcloud.tv", "samsungqbe.com", "cloudsolution.net/", "*.example.com", "0.0.0.0 example.com",
                 "example.com/1.2.3.4", "server=1.2.3.4", "127.0.0.1", "::1", "123.45", "a..com", "a.com.", "a_b.com", "-a.com", "a-.com",
                 "https://example.com", "a.com\tserver=1.2.3.4", "a\0.com", "é.com", new string('a',64) + ".com"})
            Check(Throws(() => DnsPolicy.ParseDomains("good.example\n" + bad)), "Reject whole file: " + bad);
        Check(Throws(() => DnsPolicy.ParseDomains(new string('#', DnsPolicy.MaxBlocklistBytes + 1))), "Bound blocklist size");
        var many = new System.Text.StringBuilder();
        for (int i = 0; i < DnsPolicy.MaxExtraDomains; i++) many.Append("d" + i + ".example\n");
        Check(DnsPolicy.ParseDomains(many.ToString()).Length == 259, "Accept bounded number of domains");
        Check(Throws(() => DnsPolicy.ParseDomains(many + "overflow.example\n")), "Bound extra domain count");
        Check(DnsPolicy.SafeBlocklistMetadata("regular file:0:0:600:42"), "Trusted installed file");
        Check(DnsPolicy.SafeBlocklistMetadata("regular empty file:0:0:400:0"), "Empty/read-only installed file");
        foreach (string bad in new string[] {"symbolic link:0:0:777:20", "fifo:0:0:600:0", "directory:0:0:700:0",
                 "regular file:1:0:600:42", "regular file:0:1:600:42", "regular file:0:0:666:42", "regular file:0:0:644:42",
                 "regular file:0:0:600:65537", "regular file:0:0:600:-1", "regular file:0:0:600:42\nextra", ""})
            Check(!DnsPolicy.SafeBlocklistMetadata(bad), "Reject unsafe metadata");
        string path = Path.Combine(dir, "extra-domains.conf");
        File.WriteAllText(path, "example.com\n");
        int code;
        string output = Cli(() => DnsSupervisor.Main(new string[] {"check-blocklist", path}), out code);
        Check(code == 0 && output.Contains("VALID blocked_domains=4 extra_domains=1"), "Offline blocklist validation without root");
        File.WriteAllText(path, "example.com\r\n", new System.Text.UTF8Encoding(true));
        Check(DnsPolicy.ReadDomains(path).Length == 4, "Accept UTF-8 BOM and CRLF");
        File.WriteAllText(path, "server=8.8.8.8\n");
        Cli(() => DnsSupervisor.CheckBlocklist(new string[] {"check-blocklist", path}), out code);
        Check(code == 1, "Invalid blocklist validation exits 1");
        File.WriteAllBytes(path, new byte[] {0xff,0xfe,0xff});
        Cli(() => DnsSupervisor.CheckBlocklist(new string[] {"check-blocklist", path}), out code);
        Check(code == 1, "Reject malformed encoding");
        File.WriteAllText(path, new string('#', DnsPolicy.MaxBlocklistBytes + 1));
        Check(Throws(() => DnsPolicy.ReadDomains(path)), "Oversized file refused before read");
        Cli(() => DnsSupervisor.CheckBlocklist(new string[] {"check-blocklist", path + ".missing"}), out code);
        Check(code == 1, "Missing file validation exits 1");
        Cli(() => DnsSupervisor.CheckBlocklist(new string[] {"check-blocklist"}), out code);
        Check(code == 2, "Missing path exits 2");
    }
    static void Wire() {
        byte[] p = {0x12,0x34,0x81,0x83,0,1,0,0,0,0,0,0};
        Check(DnsPolicy.BlockedReply(p,0x1234), "Accept proper NXDOMAIN");
        Check(!DnsPolicy.BlockedReply(p,0x4321), "Reject wrong ID");
        p[3]=0x80; Check(!DnsPolicy.BlockedReply(p,0x1234), "Reject NOERROR"); p[3]=0x83;
        p[7]=1; Check(!DnsPolicy.BlockedReply(p,0x1234), "Reject answer"); p[7]=0;
        p[2]=0x83; Check(!DnsPolicy.BlockedReply(p,0x1234), "Reject truncated reply"); p[2]=0x81;
        p[5]=0; Check(!DnsPolicy.BlockedReply(p,0x1234), "Reject absent question");
        Check(!DnsPolicy.BlockedReply(new byte[5],0x1234), "Reject short reply");
        Check(BitConverter.ToString(DnsPolicy.Query(0x1234, "osb.samsungqbe.com", 28)) ==
            "12-34-01-00-00-01-00-00-00-00-00-00-03-6F-73-62-0A-73-61-6D-73-75-6E-67-71-62-65-03-63-6F-6D-00-00-1C-00-01",
            "Query wire format");
    }
    static void Listeners() {
        Check(DnsPolicy.HoldsPort53("   0: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1", true), "TCP listener holds port 53");
        Check(DnsPolicy.HoldsPort53("   0: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 0A 00000000:00000000", true), "TCP6 listener holds port 53");
        Check(!DnsPolicy.HoldsPort53("   1: 0100007F:0035 0100007F:D431 06 00000000:00000000 03:00001770 00000000     0        0 0 3", true), "TCP TIME_WAIT does not hold port 53");
        Check(!DnsPolicy.HoldsPort53("   2: 0100007F:0035 0100007F:D432 08 00000000:00000000 00:00000000 00000000    99        0 0 1", true), "TCP CLOSE_WAIT does not hold port 53");
        Check(!DnsPolicy.HoldsPort53("   3: 0100007F:D431 0100007F:0035 0A 00000000:00000000 00:00000000 00000000     0        0 1003 1", true), "Remote port 53 is not local");
        Check(DnsPolicy.HoldsPort53(" 123: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000    99        0 1002 2", false), "Bound UDP socket holds port 53");
        Check(!DnsPolicy.HoldsPort53("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode", true), "Header row");
    }
    // Synthetic tasks file in a private temporary directory, never a real cgroup.
    static void Drain(string dir) {
        string tasks = Path.Combine(dir, "tasks");
        File.WriteAllText(tasks, "4242\n");
        var exit = new Thread(() => { Thread.Sleep(200); File.WriteAllText(tasks, ""); });
        exit.Start();
        Check(DnsSupervisor.Drained(tasks, 3000), "Group drains once killed tasks leave");
        exit.Join();
        File.WriteAllText(tasks, "4242\n");
        var clock = Stopwatch.StartNew();
        Check(!DnsSupervisor.Drained(tasks, 300) && clock.ElapsedMilliseconds < 2000, "Drain wait is bounded");
    }
    // cleanup takes the same lock as run, so it refuses while a supervisor holds it.
    static void Lock(string dir) {
        string path = Path.Combine(dir, "supervisor.lock");
        using (DnsSupervisor.Lock(path, "run")) {
            string refused = null;
            try { DnsSupervisor.Lock(path, "refused").Dispose(); } catch (IOException e) { refused = e.Message; }
            Check(refused != null && refused.StartsWith("refused"), "Held lock refuses a second holder");
        }
        DnsSupervisor.Lock(path, "Released lock is not free again").Dispose();
    }
    // Synthetic /proc/PID/status of the fixed worker after dnsmasq dropped privileges.
    static void Worker() {
        string ok = "Name:\tdnsmasq\nUmask:\t0077\nState:\tS (sleeping)\nTgid:\t4242\nPid:\t4242\nPPid:\t4200\n" +
            "Uid:\t99\t99\t99\t99\nGid:\t99\t99\t99\t99\nGroups:\t\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n" +
            "CapEff:\t0000000000000000\nCapBnd:\t00000000000034e3\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t0\n";
        Check(DnsSupervisor.ControlledWorker(ok, 4200), "Controlled worker accepted");
        Check(!DnsSupervisor.ControlledWorker(ok, 4201), "Reject foreign parent");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("Name:\tdnsmasq", "Name:\tsh"), 4200), "Reject shell before exec");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("Uid:\t99\t99\t99\t99", "Uid:\t99\t99\t0\t99"), 4200), "Reject saved UID 0");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("Gid:\t99\t99\t99\t99", "Gid:\t0\t0\t0\t0"), 4200), "Reject GID 0");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000001000"), 4200), "Reject permitted capability");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("CapEff:\t0000000000000000", "CapEff:\t0000000000003000"), 4200), "Reject effective capability");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("CapAmb:\t0000000000000000\n", ""), 4200), "Reject unknown ambient set");
        Check(!DnsSupervisor.ControlledWorker(ok.Replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"), 4200), "Reject missing no_new_privs");
    }
    // Chain and loopback ownership is scoped to the current boot; the old unscoped marker is not.
    static void Markers(string dir) {
        string marker = Path.Combine(dir, "TV_LOCAL_DNS4.owned"), boot = "11111111-2222-3333-4444-555555555555";
        Check(!DnsSupervisor.Claimed(marker, boot), "Missing marker owns nothing");
        File.WriteAllText(marker, boot + "\n");
        Check(DnsSupervisor.Claimed(marker, boot), "Current-boot marker owns");
        Check(!DnsSupervisor.Claimed(marker, "66666666-7777-8888-9999-000000000000"), "Earlier-boot marker does not own");
        File.WriteAllText(marker, "tv-local-dns-v1\n");
        Check(!DnsSupervisor.Claimed(marker, boot), "Unscoped legacy marker does not own");
    }
    static bool Throws(Action call) { try { call(); return false; } catch (IOException) { return true; } }
    static DnsSupervisor.Result Listing(int code, string text, bool truncated) {
        return new DnsSupervisor.Result {Code = code, Text = text, Truncated = truncated};
    }
    // Chain state comes only from a successful, complete table listing, and a marker goes only once
    // its chain is confirmed absent or deleted. Synthetic listings; iptables is never run.
    static void Firewall(string dir) {
        string chain = DnsPolicy.V4, marker = Path.Combine(dir, chain + ".owned");
        string table = "-P PREROUTING ACCEPT\n-P INPUT ACCEPT\n-P OUTPUT ACCEPT\n-P POSTROUTING ACCEPT\n";
        DnsSupervisor.Result absent = Listing(0, table + "-N OTHER\n-A OUTPUT -j OTHER", false);
        DnsSupervisor.Result present = Listing(0, table + "-N " + chain + "\n-A OUTPUT -j " + chain + "\n-A " + chain + " " + DnsPolicy.Rules4[1], false);
        DnsSupervisor.Result locked = Listing(4, "Another app is currently holding the xtables lock. Stopped waiting after 5s.", false);
        Check(!DnsSupervisor.Defines(absent, chain), "Complete listing without the chain proves absence");
        Check(DnsSupervisor.Defines(present, chain), "Listed chain is present");
        Check(!DnsSupervisor.Defines(Listing(0, table + "-N " + chain + "X", false), chain), "Only the exact chain name counts");
        Check(Throws(() => DnsSupervisor.Defines(locked, chain)), "Failed listing is not absence");
        Check(Throws(() => DnsSupervisor.Defines(Listing(1, table + "-N OTHER", false), chain)), "Partial output of a failed listing is not absence");
        Check(Throws(() => DnsSupervisor.Defines(Listing(0, table + "-N OTHER", true), chain)), "Truncated listing is not absence");
        Check(Throws(() => DnsSupervisor.Defines(Listing(0, "", false), chain)), "Empty listing is not absence");
        Check(DnsSupervisor.Run("/bin/sh", "-c \"i=0; while [ $i -lt 4000 ]; do echo 0123456789abcdef0123456789abcdef; i=$((i+1)); done\"").Truncated,
            "Output beyond 64 KiB is marked truncated");
        Check(!DnsSupervisor.Run("/bin/sh", "-c \"echo -P OUTPUT ACCEPT\"").Truncated, "Short output is complete");

        bool removed = false;
        File.WriteAllText(marker, "boot\n");
        Check(Throws(() => DnsSupervisor.Release(marker, () => DnsSupervisor.Defines(locked, chain), () => removed = true)) &&
            !removed && File.Exists(marker), "Failed inspection keeps the marker");
        Check(Throws(() => DnsSupervisor.Release(marker, () => DnsSupervisor.Defines(present, chain), () => { throw new IOException("-X: chain in use"); })) &&
            File.Exists(marker), "Failed removal keeps the marker");
        DnsSupervisor.Release(marker, () => DnsSupervisor.Defines(present, chain), () => removed = true);
        Check(removed && !File.Exists(marker), "Deleted chain releases the marker");
        removed = false; File.WriteAllText(marker, "boot\n");
        DnsSupervisor.Release(marker, () => DnsSupervisor.Defines(absent, chain), () => removed = true);
        Check(!removed && !File.Exists(marker), "Confirmed absence releases the marker");
    }
    // CLI run with captured output: exit code and stdout.
    static string Cli(Func<int> run, out int code) {
        TextWriter stdout = Console.Out, stderr = Console.Error;
        var output = new StringWriter();
        Console.SetOut(output); Console.SetError(new StringWriter());
        try { code = run(); return output.ToString(); }
        finally { Console.SetOut(stdout); Console.SetError(stderr); }
    }
    static int Query(int port, params string[] args) { int code; Cli(() => DnsSupervisor.Query(args, port), out code); return code; }
    // Echo the question with the given header flags and answer count.
    static byte[] Reply(byte[] query, int flags, int answers, bool wrongId) {
        var r = (byte[])query.Clone();
        if (wrongId) r[1] ^= 1;
        r[2] = (byte)(flags >> 8); r[3] = (byte)flags; r[6] = (byte)(answers >> 8); r[7] = (byte)answers;
        return r;
    }
    static void Serve(ThreadStart body) {
        new Thread(() => { try { body(); } catch (Exception) { } }) { IsBackground = true }.Start();
    }
    // The exception a bounded call (deadline 300 ms) failed with, or null; 1.5 s is the limit.
    static Exception Fails(Action call) {
        var clock = Stopwatch.StartNew();
        Exception error = null;
        try { call(); } catch (Exception e) { error = e; }
        Check(clock.ElapsedMilliseconds < 1500, "Call exceeded its bound");
        return error;
    }
    static byte[] Read(Stream s, int count) {
        var data = new byte[count];
        for (int pos = 0, n; pos < count; pos += n) if ((n = s.Read(data, pos, count - pos)) == 0) throw new IOException("EOF");
        return data;
    }
    // Fake DNS servers on ephemeral loopback ports only: no resolver, network device or root.
    static void QueryMode() {
        int code;
        Cli(() => DnsSupervisor.Main(new string[] {"query", "bad"}), out code);
        Check(code == 2, "query is dispatched before the root/installation check");
        Check(Query(9, "query", "127.1", "udp", "example.com", "1") == 2, "Reject abbreviated IPv4");
        Check(Query(9, "query", "fe80::1%2", "udp", "example.com", "1") == 2, "Reject scoped IPv6");
        Check(Query(9, "query", "127.0.0.1", "dot", "example.com", "1") == 2, "Reject transport");
        Check(Query(9, "query", "127.0.0.1", "udp", "example.com", "16") == 2, "Reject type");
        Check(Query(9, "query", "127.0.0.1", "udp", "a..example.com", "1") == 2, "Reject empty label");
        Check(Query(9, "query", "127.0.0.1", "udp", new string('a', 64) + ".com", "1") == 2, "Reject long label");
        Check(Query(9, "query", "127.0.0.1", "udp", "exa mple.com", "1") == 2, "Reject label characters");
        Check(Query(9, "query", "127.0.0.1", "udp", "example.com", "1", "x") == 2, "Reject extra argument");

        using (var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0))) {
            int port = ((IPEndPoint)udp.Client.LocalEndPoint).Port;
            udp.Client.ReceiveTimeout = 5000;
            Serve(() => { IPEndPoint from = null; byte[] r = Reply(udp.Receive(ref from), 0x8183, 0, false); udp.Send(r, r.Length, from); });
            string line = Cli(() => DnsSupervisor.Query(new string[] {"query", "127.0.0.1", "udp", "osb.samsungqbe.com", "28"}, port), out code);
            Check(code == 0 && line == "server=127.0.0.1 transport=udp name=osb.samsungqbe.com type=28 rcode=3 answers=0" + Environment.NewLine, "UDP NXDOMAIN line");
            Serve(() => { IPEndPoint from = null; byte[] r = Reply(udp.Receive(ref from), 0x8180, 1, true); udp.Send(r, r.Length, from); });
            Check(Query(port, "query", "127.0.0.1", "udp", "example.com", "1") == 1, "Reject reply with another ID");
            Check(Fails(() => DnsClient.Exchange(IPAddress.Loopback, port, false, DnsPolicy.Query(7, "example.com", 1), 300)) is SocketException,
                "Silent UDP server times out within its bound");
        }
        var tcp = new TcpListener(IPAddress.Loopback, 0);
        tcp.Start();
        try {
            int port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            Serve(() => {
                using (TcpClient peer = tcp.AcceptTcpClient()) using (NetworkStream s = peer.GetStream()) {
                    byte[] length = Read(s, 2), r = Reply(Read(s, (length[0] << 8) | length[1]), 0x8180, 2, false);
                    s.Write(new byte[] {(byte)(r.Length >> 8), (byte)r.Length}, 0, 2); s.Write(r, 0, r.Length);
                }
            });
            string line = Cli(() => DnsSupervisor.Query(new string[] {"query", "127.0.0.1", "tcp", "example.com", "1"}, port), out code);
            Check(code == 0 && line == "server=127.0.0.1 transport=tcp name=example.com type=1 rcode=0 answers=2" + Environment.NewLine, "TCP answer line");
            // A server that announces 100 bytes and then stalls must not hold the client past its deadline.
            Serve(() => {
                using (TcpClient peer = tcp.AcceptTcpClient()) using (NetworkStream s = peer.GetStream()) {
                    byte[] length = Read(s, 2); Read(s, (length[0] << 8) | length[1]);
                    s.Write(new byte[] {0, 100, 0x12}, 0, 3); Thread.Sleep(2000);
                }
            });
            Exception stalled = Fails(() => DnsClient.Exchange(IPAddress.Loopback, port, true, DnsPolicy.Query(7, "example.com", 1), 300));
            Check(stalled is IOException || stalled is TimeoutException, "Stalled TCP reply times out within the deadline");
        } finally { tcp.Stop(); }
        var closed = new TcpListener(IPAddress.Loopback, 0);
        closed.Start();
        int refusing = ((IPEndPoint)closed.LocalEndpoint).Port;
        closed.Stop();
        Check(Fails(() => DnsClient.Exchange(IPAddress.Loopback, refusing, true, DnsPolicy.Query(7, "example.com", 1), 300)) is SocketException,
            "Refused TCP connect fails with its SocketException");
        Check(Query(refusing, "query", "127.0.0.1", "tcp", "example.com", "1") == 1, "Refused TCP query exits 1");
        // Connect stall without an external address: a backlog-1 loopback listener with a full accept
        // queue drops further SYNs. The timed-out client is disposed while its connect is pending.
        var full = new TcpListener(IPAddress.Loopback, 0);
        full.Start(1);
        var fillers = new TcpClient[3];
        try {
            int port = ((IPEndPoint)full.LocalEndpoint).Port;
            for (int i = 0; i < fillers.Length; i++) {
                fillers[i] = new TcpClient(AddressFamily.InterNetwork);
                fillers[i].ConnectAsync(IPAddress.Loopback, port).ContinueWith(t => { var observed = t.Exception; }, TaskContinuationOptions.OnlyOnFaulted);
            }
            Thread.Sleep(100);
            Check(Fails(() => DnsClient.Exchange(IPAddress.Loopback, port, true, DnsPolicy.Query(7, "example.com", 1), 300)) is TimeoutException,
                "Stalled TCP connect times out within the deadline");
            Thread.Sleep(300); // The cancelled connect's late callback must not crash the process.
        } finally {
            foreach (TcpClient filler in fillers) if (filler != null) filler.Close();
            full.Stop();
        }
    }
    static int Main() {
        string dir = Path.Combine(Path.GetTempPath(), "tv-dns-tests-" + Guid.NewGuid().ToString("N"));
        try {
            Directory.CreateDirectory(dir);
            Policy(); Blocklists(dir); Wire(); Listeners(); Drain(dir); Lock(dir); Markers(dir); Firewall(dir); Worker(); QueryMode();
            Console.WriteLine("PASS configurable domain-only blocklist, parser/ownership/size limits, offline validation, loopback/upstream/drop-privilege policy, narrow DNS-only rules, NXDOMAIN and query wire format, port-53 listener states, bounded cgroup drain, run/cleanup lock, boot-scoped ownership, complete-listing chain evidence, worker credentials, read-only query mode");
            return 0;
        } catch (Exception e) { Console.Error.WriteLine(e); return 1; }
        finally { if (Directory.Exists(dir)) Directory.Delete(dir, true); }
    }
}
