using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text.Json;
using AutoScope.Engines.Core;
using AutoScope.Engines.Watch;

namespace AutoTrack.Services
{
    /// <summary>
    /// What a process (or svchost service) has been doing on the network,
    /// computed from the app's own recorded facts — no live capture needed:
    ///
    ///   frequency    connects per hour over the last 24 h + 24-bucket
    ///                histogram, from the Sysmon archive (EID 3), attributed
    ///                to the service by PID-within-lifetime joins for svchost
    ///                (spawn windows cut at the next svchost reuse of the PID)
    ///   destinations top IPs/ports with the session-verified classification
    ///   beacon       same regularity math as the Svchost Trace tab
    ///                (n ≥ 4 intervals, coefficient of variation &lt; 0.35)
    ///   volume       recorded TLS wire bytes from the Transmissions archive
    ///                (whole-image matches only — per-service attribution is
    ///                not recorded there, and the card says so)
    ///   live         established connections right now, identity corroboration
    ///
    /// Everything degrades honestly: no archive / no Sysmon → the snapshot
    /// still reports live rows and says what's missing.
    ///
    /// WinUI port (from AutoCommand.Services): the F# engines replace the C#
    /// services — SysmonArchiveService / SvchostIdentityService /
    /// TcpConnectionTable come from AutoScope.Engines.Watch and IpClassifier
    /// became IpClassification (AutoScope.Engines.Core). AutoCommand's
    /// ServiceCatalog and TransmissionsArchiveService are not part of this
    /// app: the curated Phone-Home subset of the catalog is inlined below,
    /// and the transmissions read degrades to "not recorded" (this app has
    /// no TLS recorder).
    /// </summary>
    public static class TraceMetricsService
    {
        // ── public surface ────────────────────────────────────────────────

        public sealed class Match
        {
            /// <summary>Image name, '*' wildcards ("chrome*", "msedge.exe").
            /// Null/empty when matching a service key instead.</summary>
            public string ProcessName;

            /// <summary>SCM service key — restricts to the svchost instance(s)
            /// hosting that service.</summary>
            public string ServiceKey;

            public static Match ForProcess(string name) => new() { ProcessName = name };
            public static Match ForService(string key) => new() { ServiceKey = key };

            public bool IsService => !string.IsNullOrWhiteSpace(ServiceKey);

            public string Describe() => IsService
                ? $"svchost service '{ServiceKey}'"
                : $"'{ProcessName}'";
        }

        public sealed class DestSummary
        {
            public string Ip { get; set; }
            public int Port { get; set; }
            public int Count { get; set; }
            public string Classification { get; set; }
            public string Display => $"{Ip}:{Port} ×{Count} [{Classification}]";
        }

        /// <summary>One bar of the 24-hour histogram shown in the detail
        /// pane. Height is pre-normalized (px) so XAML needs no converter.</summary>
        public sealed class BarVM
        {
            public double Height { get; set; }
            public string Label { get; set; }
        }

        public sealed class LiveConnection
        {
            public int Pid;
            public string Remote;
            public string Classification;
        }

        public enum Verdict { Unknown, Normal, Elevated }

        public sealed class Snapshot
        {
            public Match What;
            public DateTime ComputedUtc;
            public int ConnectsLast1H;
            public int ConnectsLast24H;
            public double ConnectsPerHour;          // 24-hour basis
            public List<int> HourlyBuckets = new(); // 24 buckets, oldest → newest (UTC hours)
            public int SpawnsLast24H;
            public int LiveConnectionCount;
            public List<DestSummary> Destinations = new();
            public string BeaconVerdict;            // null = none detected / too few
            public string BeaconDetail;
            public long TxBytes24H;                 // recorded TLS wire bytes (image matches only)
            public long RxBytes24H;
            public int Transmissions24H;
            public bool BytesAttributable = true;   // false for service matches
            public List<LiveConnection> Live = new();
            public string IdentityNote;
            public string ArchiveNote;              // null when the archive answered fully
            public Verdict VerdictKind;
            public string VerdictText;
        }

        /// <summary>Card view-model shared by the Phone Home and Traces tabs:
        /// plain strings so both XAML views bind identically. Properties, not
        /// fields — classic {Binding} only walks properties.</summary>
        public sealed class TraceCardVM
        {
            public string Title { get; set; }
            public string ChipProcess { get; set; }
            public string ChipImpact { get; set; }               // "" for user projects
            public string ChipImpactKind { get; set; }           // normal|medium|high|"" (drives color)
            public string Story { get; set; }
            public string MetricsLine { get; set; }
            public string BytesLine { get; set; }
            public string DestinationsLine { get; set; }
            public string BeaconLine { get; set; }
            public string IdentityLine { get; set; }
            public string VerdictText { get; set; }
            public string VerdictKind { get; set; }              // normal|elevated|unknown
            public string ReceiptsLine { get; set; } = "";       // "" when nothing suppressed
            public string Footnote { get; set; } = "";           // archive honesty notes
            public TraceMetricsService.Match What { get; set; }  // for actions
            public string ServiceKey { get; set; }               // non-null for curated cards
            public bool CanQuiet { get; set; }                   // DiagTrack-style hosts pin offered
            public bool IsQuieted { get; set; }                  // pin currently active
            public List<string> TopDestIps { get; set; } = new();// for destination blocks

            // ── master-detail extras: compact row (left) + detail pane (right) ─
            public double ConnectsPerHour { get; set; }
            public bool BeaconRegular { get; set; }
            public string RowMetrics { get; set; }
            public List<BarVM> Bars { get; set; } = new();
            public List<DestSummary> Destinations { get; set; } = new();
        }

        public static Snapshot Compute(Match what, int hours = 24)
        {
            if (hours is < 1 or > 24) hours = 24;
            var snap = new Snapshot { What = what, ComputedUtc = DateTime.UtcNow };
            var sinceUtc = snap.ComputedUtc.AddHours(-hours);

            // ── archive pass: connects, spawns, destinations, beacon ──────
            HashSet<int> liveServicePids = null;
            List<string> exclusiveGroups = null;
            if (what.IsService)
            {
                (exclusiveGroups, liveServicePids) = DetermineExclusiveGroups(what.ServiceKey);
                if (exclusiveGroups.Count == 0 && liveServicePids.Count == 0)
                    snap.ArchiveNote = "Per-service history could not be attributed: this Windows build " +
                                       "starts the service without a per-service command-line token, and " +
                                       "its svchost -k group is shared with other services. Live identity " +
                                       "below is still verified against the SCM.";
            }
            try
            {
                ScanArchive(what, sinceUtc, snap, exclusiveGroups, liveServicePids);
            }
            catch (Exception ex)
            {
                snap.ArchiveNote = "Sysmon archive unreadable (" + ex.Message + ") — showing live data only.";
            }
            if (snap.ArchiveNote == null && snap.ConnectsLast24H == 0 && snap.SpawnsLast24H == 0)
                snap.ArchiveNote = "No matching events in the archive window — either this " +
                                   (what.IsService ? "service" : "process") +
                                   " was quiet, or Sysmon/the archive is not running.";

            snap.ConnectsPerHour = hours > 0
                ? Math.Round(snap.ConnectsLast24H / (double)hours, 1) : 0;

            // ── verdict against the curated normal band, when one exists ──
            if (what.IsService && TryGetCatalog(what.ServiceKey, out var info) &&
                info.NormalMaxPerHour.HasValue)
            {
                bool normal = snap.ConnectsPerHour <= info.NormalMaxPerHour.Value;
                snap.VerdictKind = normal ? Verdict.Normal : Verdict.Elevated;
                snap.VerdictText = normal
                    ? $"Normal — typically up to ~{info.NormalMaxPerHour} connects/hr for this service"
                    : $"Above the typical band (~{info.NormalMaxPerHour} connects/hr) — worth a look, not a verdict";
            }
            else
            {
                snap.VerdictKind = Verdict.Unknown;
                snap.VerdictText = "No authored baseline for this match — the numbers are the facts";
            }

            // ── live pass: established rows + identity corroboration ─────
            try { ScanLive(what, snap); } catch { /* live table hiccup — card still useful */ }

            // ── volume: recorded TLS transmissions (whole-image only) ────
            try { SumTransmissions(what, sinceUtc, snap); } catch { /* transmissions optional */ }

            return snap;
        }

        // ── archive scan ─────────────────────────────────────────────────

        private static void ScanArchive(Match what, DateTime sinceUtc, Snapshot snap,
                                        List<string> exclusiveGroups, HashSet<int> liveServicePids)
        {
            bool byService = what.IsService;
            string serviceToken = byService ? "-s " + what.ServiceKey : null;
            var groupTokens = byService && exclusiveGroups != null
                ? exclusiveGroups.Select(g => "-k " + g).ToArray()
                : Array.Empty<string>();

            // svchost PID reuse cuts a service's attribution window at the
            // next svchost spawn of the same PID (any service). EID 3 events
            // are collected during the read and attributed AFTER the spawn
            // lists are complete and sorted — attribution depends on sorted
            // spawn history, and day files can interleave.
            var svchostSpawns = new Dictionary<int, List<(DateTime Ts, bool Ours)>>();
            var pendingConnects = new List<(int Pid, string Ip, int Port, DateTime Ts)>();
            var dests = new Dictionary<(string Ip, int Port), int>();
            var buckets = new int[24];
            string processLiteral = LongestLiteral(what.ProcessName);

            foreach (var path in ArchiveDayFiles(sinceUtc, snap.ComputedUtc))
            {
                foreach (var line in File.ReadLines(path))
                {
                    // cheap prefilter before paying for JSON: the token must
                    // appear in the line at all (image name, or svchost.exe
                    // for the service join)
                    string token = byService ? "svchost.exe" : processLiteral;
                    if (string.IsNullOrEmpty(token) ||
                        !line.Contains(token, StringComparison.OrdinalIgnoreCase)) continue;

                    using var doc = JsonDocument.Parse(line);
                    var root = doc.RootElement;
                    if (!root.TryGetProperty("eid", out var eidEl)) continue;
                    int eid = eidEl.GetInt32();
                    if (eid != 1 && eid != 3) continue;
                    if (!root.TryGetProperty("ts", out var tsEl) ||
                        !DateTime.TryParse(tsEl.GetString(), CultureInfo.InvariantCulture,
                            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var ts) ||
                        ts < sinceUtc) continue;
                    if (!root.TryGetProperty("data", out var dataEl)) continue;

                    string image = GetString(dataEl, "Image") ?? "";
                    string imageName = Path.GetFileName(image);

                    if (eid == 1)
                    {
                        if (byService)
                        {
                            if (!imageName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) continue;
                            string cmd = GetString(dataEl, "CommandLine") ?? "";
                            int pid = GetInt(dataEl, "ProcessId");
                            // three ways a spawn claims this service: an
                            // explicit "-s <key>" token (older builds);
                            // membership of a -k group that live SCM data
                            // shows hosts this service exclusively
                            // (split-service builds launch with no -s token);
                            // or the pid being LIVE right now hosting the
                            // service — its own spawn event is by definition
                            // this process's, shared group or not
                            bool ours = (serviceToken != null &&
                                         cmd.Contains(serviceToken, StringComparison.OrdinalIgnoreCase)) ||
                                        groupTokens.Any(t => CommandHasGroup(cmd, t)) ||
                                        (liveServicePids != null && liveServicePids.Contains(pid));
                            if (!svchostSpawns.TryGetValue(pid, out var list))
                                svchostSpawns[pid] = list = new List<(DateTime, bool)>();
                            list.Add((ts, ours));
                            if (ours) snap.SpawnsLast24H++;
                        }
                        else
                        {
                            if (!NameMatches(imageName, what.ProcessName)) continue;
                            snap.SpawnsLast24H++;
                        }
                        continue;
                    }

                    // eid == 3: collect now, attribute after the read loop
                    if (byService)
                    {
                        if (!imageName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)) continue;
                        pendingConnects.Add((GetInt(dataEl, "ProcessId"),
                            GetString(dataEl, "DestinationIp"), GetInt(dataEl, "DestinationPort"), ts));
                    }
                    else
                    {
                        if (!NameMatches(imageName, what.ProcessName)) continue;
                        pendingConnects.Add((GetInt(dataEl, "ProcessId"),
                            GetString(dataEl, "DestinationIp"), GetInt(dataEl, "DestinationPort"), ts));
                    }
                }
            }

            foreach (var list in svchostSpawns.Values)
                list.Sort((a, b) => a.Ts.CompareTo(b.Ts));

            var beaconTimes = new List<(int Pid, string Ip, DateTime Ts)>();
            foreach (var (pid, ip, port, ts) in pendingConnects)
            {
                if (byService && !AttributedToService(svchostSpawns, pid, ts)) continue;

                snap.ConnectsLast24H++;
                if (ts >= snap.ComputedUtc.AddHours(-1)) snap.ConnectsLast1H++;
                int bucket = (int)((ts - sinceUtc).TotalHours);
                if (bucket >= 0 && bucket < 24) buckets[bucket]++;

                if (!string.IsNullOrEmpty(ip) && !IsLoopback(ip))
                {
                    var key = (ip, port);
                    dests[key] = dests.TryGetValue(key, out var c) ? c + 1 : 1;
                    beaconTimes.Add((pid, ip, ts));
                }
            }

            snap.HourlyBuckets = buckets.ToList();
            snap.Destinations = dests
                .OrderByDescending(kv => kv.Value)
                .Take(8)
                .Select(kv => new DestSummary
                {
                    Ip = kv.Key.Ip,
                    Port = kv.Key.Port,
                    Count = kv.Value,
                    Classification = SafeClassify(kv.Key.Ip),
                })
                .ToList();

            AnalyzeBeacon(beaconTimes, snap);
        }

        /// <summary>Latest svchost spawn of this PID at/before the event —
        /// the event belongs to our service only if that spawn was ours
        /// (a later spawn of the same PID by another service ends the
        /// window; PID reuse beyond that is the known, disclosed limit).</summary>
        private static bool AttributedToService(
            Dictionary<int, List<(DateTime Ts, bool Ours)>> spawns, int pid, DateTime ts)
        {
            if (!spawns.TryGetValue(pid, out var list) || list.Count == 0) return false;
            // lists are sorted after the read loop; events can arrive out of
            // order across day files, so binary-search defensively
            int lo = 0, hi = list.Count - 1, found = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (list[mid].Ts <= ts) { found = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            return found >= 0 && list[found].Ours;
        }

        private static void AnalyzeBeacon(List<(int Pid, string Ip, DateTime Ts)> times, Snapshot snap)
        {
            foreach (var g in times.GroupBy(t => (t.Pid, t.Ip)))
            {
                var sorted = g.Select(t => t.Ts).OrderBy(t => t).ToList();
                if (sorted.Count < 4) continue;
                var intervals = sorted.Zip(sorted.Skip(1), (a, b) => (b - a).TotalSeconds).ToList();
                double mean = intervals.Average();
                if (mean <= 0) continue;
                double std = Math.Sqrt(intervals.Sum(v => (v - mean) * (v - mean)) / intervals.Count);
                double cv = std / mean;
                if (cv < 0.35)
                {
                    snap.BeaconVerdict = "Regular-interval pattern detected";
                    snap.BeaconDetail = $"{g.Key.Ip}: n={sorted.Count}, mean {mean:F0}s, CV {cv:F2} — " +
                                        "beacon-like regularity (same math as the Svchost Trace tab)";
                    return;
                }
            }
            snap.BeaconVerdict = null;
            snap.BeaconDetail = snap.ConnectsLast24H >= 4
                ? "No regular-interval pattern across " + snap.ConnectsLast24H + " connects (irregular — normal)"
                : null;
        }

        /// <summary>"-k group" token with a word boundary at the end, so
        /// "-k netsvcs" never matches "-k netsvcsRedirectionGuard".</summary>
        private static bool CommandHasGroup(string cmd, string groupToken)
        {
            int ix = cmd.IndexOf(groupToken, StringComparison.OrdinalIgnoreCase);
            while (ix >= 0)
            {
                int end = ix + groupToken.Length;
                if (end == cmd.Length || cmd[end] == ' ' || cmd[end] == '"')
                    return true;
                ix = cmd.IndexOf(groupToken, ix + 1, StringComparison.OrdinalIgnoreCase);
            }
            return false;
        }

        /// <summary>
        /// The -k groups that, per live SCM ground truth, host exactly this
        /// one service — the only groups whose historical events can be
        /// attributed to the service honestly. Shared groups (NetworkService,
        /// netsvcs…) are excluded on purpose: counting them would count other
        /// services' traffic too. Plus a tiny built-in map for known-unique
        /// groups, so attribution survives the service not running right now.
        /// Also returns the live PIDs currently hosting the service — their
        /// own spawn windows are attributable regardless of group sharing.
        /// </summary>
        private static (List<string> Groups, HashSet<int> LivePids) DetermineExclusiveGroups(string serviceKey)
        {
            var groups = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var livePids = new HashSet<int>();
            foreach (var p in Process.GetProcessesByName("svchost"))
            {
                try
                {
                    var id = SvchostIdentityService.Resolve(p.Id);
                    if (id == null) continue;
                    if ((id.ServicesCsv ?? "").Split(',')
                            .Any(s => s.Trim().Equals(serviceKey, StringComparison.OrdinalIgnoreCase)))
                        livePids.Add(p.Id);
                    if (string.IsNullOrEmpty(id.Group)) continue;
                    if (!groups.TryGetValue(id.Group, out var set))
                        groups[id.Group] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    foreach (var svc in (id.ServicesCsv ?? "").Split(','))
                        if (svc.Trim().Length > 0) set.Add(svc.Trim());
                }
                catch { /* a dying process answers nothing */ }
                finally { try { p.Dispose(); } catch { } }
            }

            var result = groups
                .Where(kv => kv.Value.Count == 1 &&
                             kv.Value.First().Equals(serviceKey, StringComparison.OrdinalIgnoreCase))
                .Select(kv => kv.Key)
                .ToList();

            if (serviceKey.Equals("diagtrack", StringComparison.OrdinalIgnoreCase) &&
                !result.Contains("utcsvc", StringComparer.OrdinalIgnoreCase))
                result.Add("utcsvc"); // known-unique telemetry group

            return (result, livePids);
        }

        // ── live pass ────────────────────────────────────────────────────

        private static void ScanLive(Match what, Snapshot snap)
        {
            var procNames = new Dictionary<int, string>();
            foreach (var p in Process.GetProcesses())
            {
                try { procNames[p.Id] = p.ProcessName + ".exe"; } catch { }
                finally { try { p.Dispose(); } catch { } }
            }

            bool byService = what.IsService;
            var servicePids = new List<int>();
            int corroborated = 0, mismatched = 0;

            // identity comes from every live svchost instance hosting the
            // service — a service can be running perfectly well with zero
            // established connections right now, and "no live instance"
            // would be a lie
            if (byService)
            {
                foreach (var p in Process.GetProcesses())
                {
                    try
                    {
                        if (!p.ProcessName.Equals("svchost", StringComparison.OrdinalIgnoreCase)) continue;
                        var id = SvchostIdentityService.Resolve(p.Id);
                        if (id == null || !ServiceCsvMatches(id.ServicesCsv, what.ServiceKey)) continue;
                        servicePids.Add(p.Id);
                        if (id.Mismatch) mismatched++; else corroborated++;
                    }
                    catch { /* a dying process answers nothing — skip it */ }
                    finally { try { p.Dispose(); } catch { } }
                }
                snap.IdentityNote = servicePids.Count == 0
                    ? "No live svchost instance hosting this service right now"
                    : mismatched > 0
                        ? $"⚠ {mismatched} of {servicePids.Count} live instance(s): command line does NOT corroborate SCM — masquerade signal"
                        : $"Identity corroborated: {servicePids.Count} live instance(s), command lines match SCM";
            }

            foreach (var row in TcpConnectionTable.GetEstablished())
            {
                if (IsLoopback(row.RemoteIp)) continue;
                if (!procNames.TryGetValue(row.Pid, out var image)) continue;

                if (byService)
                {
                    if (!servicePids.Contains(row.Pid)) continue;
                }
                else if (!NameMatches(image, what.ProcessName)) continue;

                snap.Live.Add(new LiveConnection
                {
                    Pid = row.Pid,
                    Remote = row.RemoteEndPoint,
                    Classification = SafeClassify(row.RemoteIp),
                });
            }

            snap.LiveConnectionCount = snap.Live.Count;

            if (!byService)
            {
                int instances = procNames.Values.Count(n => NameMatches(n, what.ProcessName));
                snap.IdentityNote = instances == 0
                    ? "Not running right now"
                    : $"{instances} live instance(s)";
            }
        }

        private static bool ServiceCsvMatches(string servicesCsv, string key)
        {
            if (string.IsNullOrEmpty(servicesCsv) || string.IsNullOrEmpty(key)) return false;
            return servicesCsv.Split(',')
                .Select(s => s.Trim())
                .Any(s => s.Equals(key, StringComparison.OrdinalIgnoreCase));
        }

        // ── recorded volume ──────────────────────────────────────────────

        private static void SumTransmissions(Match what, DateTime sinceUtc, Snapshot snap)
        {
            // WinUI port: AutoCommand's TransmissionsArchiveService (recorded
            // TLS wire bytes) is not part of this app — AutoTrack has no TLS
            // recorder, so there is nothing honest to read. Keep the original
            // degradation: say the bytes are not recorded rather than guess.
            // (The only view hosted here matches services, which took this
            // branch in the original too.)
            snap.BytesAttributable = false;
        }

        // ── shared helpers ───────────────────────────────────────────────

        /// <summary>Wildcard-aware image-name match ('*' spans anything,
        /// '?' one char); no wildcards = exact, case-insensitive.</summary>
        public static bool NameMatches(string imageName, string pattern)
        {
            if (string.IsNullOrWhiteSpace(pattern)) return false;
            if (pattern.IndexOfAny(new[] { '*', '?' }) < 0)
                return string.Equals(imageName, pattern, StringComparison.OrdinalIgnoreCase);
            // translate to a regex — patterns are short, this is cheap
            var regex = "^" + string.Join("",
                pattern.Select(c => c switch
                {
                    '*' => ".*",
                    '?' => ".",
                    _ => System.Text.RegularExpressions.Regex.Escape(c.ToString()),
                })) + "$";
            return System.Text.RegularExpressions.Regex.IsMatch(
                imageName, regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        }

        /// <summary>Longest literal run in a wildcard pattern — used as the
        /// line prefilter token ("" when the pattern is all wildcards, in
        /// which case every line is parsed; "*.exe" is the usual worst case
        /// and callers are expected to pass saner patterns).</summary>
        private static string LongestLiteral(string pattern)
        {
            if (string.IsNullOrEmpty(pattern)) return null;
            string best = "";
            foreach (var part in pattern.Split('*', '?'))
                if (part.Length > best.Length) best = part;
            return best.Length == 0 ? null : best;
        }

        private static IEnumerable<string> ArchiveDayFiles(DateTime sinceUtc, DateTime nowUtc)
        {
            // WinUI port (engine): the F# SysmonArchiveService keeps
            // DayFilePath private; the archive ROOT is public and the file
            // name contract is stable, so build the same day-file paths here
            // (ArchiveDirectory derives from the configured identity's
            // DataRoot — %LOCALAPPDATA%\AutoTrack in this app).
            for (var day = sinceUtc.Date; day <= nowUtc.Date; day = day.AddDays(1))
            {
                var path = Path.Combine(SysmonArchiveService.ArchiveDirectory,
                    "sysmon-archive-" + day.ToString("yyyy-MM-dd") + ".jsonl");
                if (File.Exists(path)) yield return path;
            }
        }

        private static bool IsLoopback(string ip) =>
            ip != null && (ip.StartsWith("127.") || ip == "::1" || ip == "0.0.0.0");

        private static string SafeClassify(string ip)
        {
            // WinUI port (engine): IpClassifier → IpClassification (F#)
            try { return IpClassification.Classify(ip); }
            catch { return "unclassified"; }
        }

        private static string GetString(JsonElement data, string key) =>
            data.TryGetProperty(key, out var el) && el.ValueKind == JsonValueKind.String
                ? el.GetString() : null;

        // Sysmon EventData renders every value as a string in the archive
        // ("ProcessId":"2264"), but hand-written lines may use numbers —
        // accept both, never guess.
        private static int GetInt(JsonElement data, string key)
        {
            if (!data.TryGetProperty(key, out var el)) return 0;
            if (el.ValueKind == JsonValueKind.Number) return el.GetInt32();
            return el.ValueKind == JsonValueKind.String &&
                   int.TryParse(el.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v)
                ? v : 0;
        }

        // ── card view-model shared by both tabs ──────────────────────────

        /// <summary>Formats a snapshot into the plain-string card VM both
        /// the Phone Home and Traces tabs bind to. Impact chip and story
        /// come from the catalog when the match is a curated service; the
        /// caller can override either for user projects.</summary>
        public static TraceCardVM BuildCardVM(Snapshot snap, string storyOverride = null)
        {
            var vm = new TraceCardVM { What = snap.What };

            if (snap.What.IsService && TryGetCatalog(snap.What.ServiceKey, out var info))
            {
                vm.Title = info.DisplayName;
                vm.ChipProcess = snap.What.ServiceKey;
                vm.ChipImpact = info.Impact switch
                {
                    ServiceImpact.High => "high impact if blocked",
                    ServiceImpact.Medium => "medium impact if blocked",
                    _ => "safe to block",
                };
                vm.ChipImpactKind = info.Impact switch
                {
                    ServiceImpact.High => "high",
                    ServiceImpact.Medium => "medium",
                    _ => "normal",
                };
                vm.Story = storyOverride ?? info.PhoneHomeStory ?? info.Description;
                vm.ServiceKey = snap.What.ServiceKey;
            }
            else
            {
                vm.Title = snap.What.ProcessName ?? "(unset)";
                vm.ChipProcess = snap.What.IsService ? snap.What.ServiceKey : "process";
                vm.ChipImpact = "";
                vm.ChipImpactKind = "";
                vm.Story = storyOverride ?? "";
            }

            vm.MetricsLine =
                $"{snap.ConnectsPerHour} connects/hr · {snap.ConnectsLast24H} in the last 24 h " +
                $"({snap.ConnectsLast1H} in the last hour) · {snap.LiveConnectionCount} live now · " +
                $"{snap.SpawnsLast24H} process starts in 24 h";

            vm.BytesLine = snap.BytesAttributable
                ? $"Recorded TLS volume, 24 h: sent {snap.TxBytes24H:N0} B · received {snap.RxBytes24H:N0} B " +
                  $"across {snap.Transmissions24H} recorded flow(s)"
                : "Per-service TLS bytes are not recorded — Transmissions attributes to svchost.exe as a whole";

            vm.DestinationsLine = snap.Destinations.Count == 0
                ? "No destinations in the archive window"
                : string.Join("   ", snap.Destinations.Take(5).Select(d =>
                    $"{d.Ip}:{d.Port} ×{d.Count} [{d.Classification}]"));

            vm.BeaconLine = snap.BeaconVerdict != null
                ? $"⚠ {snap.BeaconVerdict} — {snap.BeaconDetail}"
                : snap.BeaconDetail ?? "Too few connects to assess regularity";

            vm.IdentityLine = snap.IdentityNote ?? "";
            vm.VerdictText = snap.VerdictText ?? "";
            vm.VerdictKind = snap.VerdictKind switch
            {
                Verdict.Normal => "normal",
                Verdict.Elevated => "elevated",
                _ => "unknown",
            };
            vm.Footnote = snap.ArchiveNote ?? "";
            vm.TopDestIps = snap.Destinations.Select(d => d.Ip).Take(3).ToList();

            // master-detail extras
            vm.ConnectsPerHour = snap.ConnectsPerHour;
            vm.BeaconRegular = snap.BeaconVerdict != null;
            vm.RowMetrics = $"{snap.ConnectsPerHour}/hr · {snap.ConnectsLast24H} in 24h · {snap.LiveConnectionCount} live";
            vm.Destinations = snap.Destinations;
            int maxBucket = snap.HourlyBuckets.Count > 0 ? snap.HourlyBuckets.Max() : 0;
            vm.Bars = snap.HourlyBuckets
                .Select((b, i) => new BarVM
                {
                    Height = b == 0 ? 1 : 2 + 34.0 * b / maxBucket,
                    Label = $"{23 - i}h ago · {b} connect(s)",
                })
                .ToList();
            return vm;
        }

        // ── distinct image names seen recently (New-project autocomplete) ─

        public static List<string> RecentProcessNames(int minutes = 120)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sinceUtc = DateTime.UtcNow.AddMinutes(-Math.Clamp(minutes, 5, 1440));
            try
            {
                foreach (var path in ArchiveDayFiles(sinceUtc, DateTime.UtcNow))
                    foreach (var line in File.ReadLines(path))
                    {
                        int ix = line.IndexOf("\"Image\"", StringComparison.Ordinal);
                        if (ix < 0) continue;
                        using var doc = JsonDocument.Parse(line);
                        if (!doc.RootElement.TryGetProperty("eid", out var e) ||
                            (e.GetInt32() != 1 && e.GetInt32() != 3)) continue;
                        var name = Path.GetFileName(GetString(doc.RootElement.GetProperty("data"), "Image") ?? "");
                        if (name.Length > 0) names.Add(name);
                        if (names.Count > 300) return names.OrderBy(n => n).ToList();
                    }
            }
            catch { /* archive missing — fall through to live processes */ }
            foreach (var p in Process.GetProcesses())
            {
                try { names.Add(p.ProcessName + ".exe"); } catch { }
                finally { try { p.Dispose(); } catch { } }
            }
            return names.OrderBy(n => n).ToList();
        }

        // ── curated Phone-Home catalog (inlined subset) ───────────────────
        //
        // WinUI port: AutoCommand's ServiceCatalog.cs is not part of this
        // app, so the SMALLEST subset that keeps this view honest is inlined
        // here: exactly the curated Phone-Home card set (8 services), with
        // the authored display name, impact, description, story and normal
        // band verbatim from the AutoCommand catalog. Private for internal
        // use; the view reaches it through CuratedPhoneHomeKeys and the
        // string-typed TryGetCatalog overload below.

        private enum ServiceImpact { Normal = 0, Medium = 1, High = 2 }

        private sealed class ServiceInfo
        {
            public string DisplayName;
            public string Description;
            public ServiceImpact Impact;

            /// <summary>Phone Home tab only: the authored "why does this phone
            /// home, and what does normal look like" story. Null on entries
            /// that are not part of the curated Phone Home card set.</summary>
            public string PhoneHomeStory;

            /// <summary>Phone Home tab only: the upper edge of the typical
            /// connects-per-hour band, from observed behavior on ordinary
            /// machines. Null = no authored baseline (the card says so).</summary>
            public int? NormalMaxPerHour;
        }

        private static ServiceInfo Cat(string displayName, ServiceImpact impact, string description,
                                       string story, int? maxPerHour) =>
            new() { DisplayName = displayName, Description = description, Impact = impact,
                    PhoneHomeStory = story, NormalMaxPerHour = maxPerHour };

        private static readonly Dictionary<string, ServiceInfo> Catalog = new()
        {
            ["wuauserv"] = Cat("Windows Update", ServiceImpact.High,
                "Downloads and installs Windows updates. Blocking it stops security patches from arriving.",
                "Talks to Windows Update during scans and downloads — bursts while updates are being fetched or installed, near-zero the rest of the day.",
                20),
            ["dosvc"] = Cat("Delivery Optimization", ServiceImpact.Medium,
                "Peers/CDN delivery of Windows Update and Store content — most Akamai/Gcore traffic from svchost is this service.",
                "Fetches Windows Update and Store content from Microsoft CDNs (and LAN peers). Sudden bursts during updates are expected; a steady all-day hum is not.",
                40),
            ["bits"] = Cat("Background Intelligent Transfer", ServiceImpact.Medium,
                "Throttled background file transfers used by updates, Defender and administrators.",
                "Carries background file transfers — updates, Defender signature jobs, admin scripts — over HTTP(S) in throttled pieces, so connects come in small clusters.",
                15),
            ["cryptsvc"] = Cat("Cryptographic Services", ServiceImpact.Medium,
                "Root-certificate trust and catalog verification — blocking breaks HTTPS for system components.",
                "Fetches certificate revocation lists and root-certificate updates on behalf of every program doing TLS. Plain port-80 fetches to Cloudflare/Google CDNs are normal — CRLs are signed, so they travel unencrypted by design. Its rate tracks how much TLS the whole machine is doing.",
                30),
            ["wpnservice"] = Cat("Windows Push Notifications", ServiceImpact.Medium,
                "Delivers live tiles, toasts and app notifications (WNS channel).",
                "Keeps a channel open to the Windows Push Notification service and cycles it periodically — that is how toasts, live tiles and app notifications arrive.",
                12),
            ["netprofm"] = Cat("Network List Service", ServiceImpact.Medium,
                "Reports network connectivity and properties to apps. Its probes hit Microsoft/Akamai edges; blocking can flip the taskbar to 'no internet' and break Store/Start web content.",
                "Reports network connectivity and properties to apps; probes Microsoft/Akamai edges whenever the network state changes (Wi-Fi roam, VPN up/down, resume).",
                12),
            ["wlidsvc"] = Cat("Microsoft Account Sign-in", ServiceImpact.Medium,
                "Sign-in helper for Microsoft accounts.",
                "Sign-in helper for Microsoft accounts — checks identity and token endpoints when apps sign in or silently refresh credentials.",
                10),
            ["diagtrack"] = Cat("Connected User Experiences (DiagTrack)", ServiceImpact.Normal,
                "Windows diagnostic/telemetry upload. A legitimate blocking target if you want less telemetry.",
                "Batches Windows diagnostic/usage data and uploads it to Microsoft on a timer — roughly every 15–40 minutes, usually over one long-lived TLS connection rather than rapid beacons.",
                6),
        };

        /// <summary>The Phone Home tab's curated card set, in display order
        /// (the tab re-sorts by measured connects/hour). Every key here has
        /// an authored PhoneHomeStory and a normal band.</summary>
        public static readonly string[] CuratedPhoneHomeKeys =
        {
            "diagtrack", "cryptsvc", "dosvc", "wpnservice",
            "wlidsvc", "netprofm", "wuauserv", "bits",
        };

        private static bool TryGetCatalog(string serviceKey, out ServiceInfo info) =>
            Catalog.TryGetValue((serviceKey ?? "").Trim().ToLowerInvariant(), out info) &&
            !string.IsNullOrEmpty(serviceKey);

        /// <summary>Impact + description for the view's block-confirm
        /// warning — impactKind is "high"|"medium"|"normal" (the enum stays
        /// private; the card VM already carries the display strings).</summary>
        public static bool TryGetCatalog(string serviceKey, out string description, out string impactKind)
        {
            description = null;
            impactKind = null;
            if (!TryGetCatalog(serviceKey, out var info)) return false;
            description = info.Description;
            impactKind = info.Impact switch
            {
                ServiceImpact.High => "high",
                ServiceImpact.Medium => "medium",
                _ => "normal",
            };
            return true;
        }
    }
}
