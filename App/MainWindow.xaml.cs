using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using AutoScope.Engines.Core;
using AutoScope.Engines.Watch;
using AutoScope.Engines.Firewall;
using Identity = AutoScope.Engines.Core.Identity;

namespace AutoTrack
{
    public sealed class TrackRow
    {
        public DateTime TimeUtc { get; set; }
        public string TimeDisplay => TimeUtc == default ? "—" : TimeUtc.ToLocalTime().ToString("HH:mm:ss");
        public string Service { get; set; }
        public int Pid { get; set; }
        public string RemoteIp { get; set; }
        public int RemotePort { get; set; }
        public string RemoteEndpoint => $"{RemoteIp}:{RemotePort}";
        public string State { get; set; }          // Established | Attempt | Blocked
        public string Class { get; set; }
        public string BlockedBy { get; set; }      // AutoCommand | AutoScope | ""
        public string Hostname { get; set; }
    }

    /// <summary>
    /// The tracker: every connect ATTEMPT (Sysmon EID 3 sees them even when a
    /// firewall block drops them — the TCP table never will) plus every
    /// ESTABLISHED connection from the kernel's dual-family table, filtered
    /// to the services on your blocked list. Read-only; blocks are reported
    /// with their owner, never created or changed here.
    /// </summary>
    public partial class MainWindow : Window
    {
        private readonly DispatcherQueue _dq;
        private readonly DispatcherQueueTimer _poll;
        private readonly DispatcherQueueTimer _blocksTimer;

        private readonly AutoScope.Engines.Firewall.FirewallService _fw;
        private readonly SysmonConnectWatcherService _connects = new();

        // ip → which app's block rule
        private readonly Dictionary<string, string> _blockedByIp = new(StringComparer.OrdinalIgnoreCase);
        // service keys tracked (base set + whatever the blocked list names)
        private readonly ObservableCollection<(string Key, ToggleButton Btn)> _chips = new();
        private readonly HashSet<string> _trackedServices = new(StringComparer.OrdinalIgnoreCase)
            { "cryptsvc", "diagtrack", "netprofm", "wuauserv", "wlidsvc", "dosvc", "wpnservice", "msedgewebview2" };
        private readonly ObservableCollection<TrackRow> _rows = new();
        // pid → (exe name lower, svchost identity, stamp)
        private readonly Dictionary<int, (string Exe, SvchostPidIdentity Id, DateTime Stamp)> _pidCache = new();
        private bool _paused;

        private static string AppVersion =>
            FileVersionInfo.GetVersionInfo(Environment.ProcessPath).ProductVersion ?? "?";

        public MainWindow()
        {
            InitializeComponent();
            _dq = DispatcherQueue.GetForCurrentThread();

            try
            {
                var tb = AppWindow.TitleBar;
                tb.ButtonForegroundColor = Microsoft.UI.Colors.LightGray;
                tb.ButtonBackgroundColor = Windows.UI.Color.FromArgb(255, 0x17, 0x1B, 0x22);
                tb.ButtonInactiveBackgroundColor = Windows.UI.Color.FromArgb(255, 0x17, 0x1B, 0x22);
            }
            catch { }

            FooterText.Text = $"AutoTrack v{AppVersion} — reads only (TCP table, Sysmon, firewall inventory). " +
                              "Blocks are reported, never created or changed here.";

            WatchConfig.Configure(Identity.autotrack());
            // adopts BOTH apps' rules so blocked-by names the owner; own
            // prefixes are inert (this app never blocks)
            var adoptBoth = Microsoft.FSharp.Collections.ListModule.OfArray(
                new[] { "AC-BLOCK-IP ", "AC-BLOCK-APP ", "AS-BLOCK-IP ", "AS-BLOCK-APP " });
            var naming = new FirewallNaming(
                "AT-TRACK-IP ", "AT-TRACK-APP ", adoptBoth,
                Microsoft.FSharp.Collections.ListModule.Empty<string>(),
                Microsoft.FSharp.Collections.ListModule.Empty<string>(), "AutoTrack (unused)");
            _fw = new AutoScope.Engines.Firewall.FirewallService(naming);

            TrackGrid.ItemsSource = _rows;
            BuildChips();

            // every connect attempt, live — including the ones blocks drop
            _connects.OnConnect += e => _dq.TryEnqueue(() => OnConnectAttempt(e));
            _connects.OnError += err => _dq.TryEnqueue(() => StatusText.Text = "Sysmon: " + err);

            _poll = _dq.CreateTimer();
            _poll.Interval = TimeSpan.FromSeconds(5);
            _poll.Tick += (_, _) => PollEstablished();
            _poll.Start();

            _blocksTimer = _dq.CreateTimer();
            _blocksTimer.Interval = TimeSpan.FromSeconds(30);
            _blocksTimer.Tick += (_, _) => _ = RefreshBlocksAsync();
            _blocksTimer.Start();

            _ = RefreshBlocksAsync();
            _ = Task.Run(() =>
            {
                try { _connects.Start(); _dq.TryEnqueue(() => StatusText.Text = "live"); }
                catch (Exception ex)
                {
                    _dq.TryEnqueue(() => StatusText.Text = "Sysmon unavailable — TCP table only (" + ex.Message + ")");
                }
            });
        }

        // ── blocked inventory + tracked-service discovery ──────────────────

        private async Task RefreshBlocksAsync()
        {
            try
            {
                var rules = await _fw.LoadRulesAsync(2); // outbound, where the blocks live
                var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var r in rules)
                {
                    string owner = OwnerFromRuleName(r.Name);
                    if (owner == null) continue;
                    string ip = IpFromRuleName(r.Name);
                    if (ip != null) map[ip] = owner;

                    // blocked-list provenance names the service behind each
                    // block ("cryptsvc/Akamai…") — track those services too
                    var svc = (string)null; // via inventory below
                    if (svc != null && _trackedServices.Add(svc))
                        _dq.TryEnqueue(() => AddChip(svc));
                }
                lock (_blockedByIp)
                {
                    _blockedByIp.Clear();
                    foreach (var kv in map) _blockedByIp[kv.Key] = kv.Value;
                }
                // blocked-target provenance ("cryptsvc/Akamai…") names more
                // services worth tracking
                var inv = await _fw.GetBlockedInventoryAsync();
                var extras = new List<string>();
                foreach (var t in inv)
                {
                    var svc = ServiceFromProvenance(t.Description);
                    if (svc != null && _trackedServices.Add(svc)) extras.Add(svc);
                }
                foreach (var x in extras) _dq.TryEnqueue(() => AddChip(x));
                _dq.TryEnqueue(() =>
                    StatusText.Text = $"live · {_blockedByIp.Count} blocked address(es) · {_trackedServices.Count} services tracked");
            }
            catch (Exception ex)
            {
                _dq.TryEnqueue(() => StatusText.Text = "block refresh failed: " + ex.Message);
            }
        }

        private static string OwnerFromRuleName(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            if (name.StartsWith("AC-BLOCK-", StringComparison.OrdinalIgnoreCase)) return "AutoCommand";
            if (name.StartsWith("AS-BLOCK-", StringComparison.OrdinalIgnoreCase)) return "AutoScope";
            return null;
        }

        private static string IpFromRuleName(string name)
        {
            // "AC-BLOCK-IP 1.2.3.4 (TCP Out)"
            int cut = name.IndexOf('(');
            string head = (cut > 0 ? name.Substring(0, cut) : name).Trim();
            int sp = head.LastIndexOf(' ');
            if (sp <= 0) return null;
            string ip = head[(sp + 1)..].Trim();
            return System.Net.IPAddress.TryParse(ip, out _) ? ip : null;
        }

        private static string ServiceFromProvenance(string description)
        {
            if (string.IsNullOrEmpty(description)) return null;
            int slash = description.IndexOf('/');
            if (slash <= 0) return null;
            string svc = description[..slash].Trim().ToLowerInvariant();
            return svc.Length is > 2 and < 24 && svc.All(char.IsLetterOrDigit) ? svc : null;
        }

        // ── attribution ────────────────────────────────────────────────────

        private (string Exe, SvchostPidIdentity Id) Identify(int pid)
        {
            if (_pidCache.TryGetValue(pid, out var hit) && DateTime.UtcNow - hit.Stamp < TimeSpan.FromSeconds(30))
                return (hit.Exe, hit.Id);
            string exe = null;
            SvchostPidIdentity id = null;
            try
            {
                using var p = Process.GetProcessById(pid);
                exe = p.ProcessName?.ToLowerInvariant();
            }
            catch { /* exited — svchost identity may still resolve from SCM */ }
            if (exe == "svchost")
            {
                try { id = SvchostIdentityService.Resolve(pid); } catch { }
            }
            _pidCache[pid] = (exe, id, DateTime.UtcNow);
            return (exe, id);
        }

        /// <summary>Which tracked service (if any) owns this pid, or null.</summary>
        private string ServiceFor(int pid, string imageOverride = null)
        {
            var (exe, id) = Identify(pid);
            if (imageOverride != null) exe = Path.GetFileName(imageOverride).ToLowerInvariant().Replace(".exe", "");
            if (exe == "msedgewebview2") return _trackedServices.Contains("msedgewebview2") ? "msedgewebview2" : null;
            if (exe != "svchost" || id == null) return null;
            // -k group ("netsvcs", "NetworkService") or the -s declared
            // service — match either against the tracked set
            if (!string.IsNullOrEmpty(id.DeclaredService) && _trackedServices.Contains(id.DeclaredService))
                return id.DeclaredService;
            if (!string.IsNullOrEmpty(id.Group) && _trackedServices.Contains(id.Group))
                return id.Group;
            return null;
        }

        // ── feeds ──────────────────────────────────────────────────────────

        private void OnConnectAttempt(SysmonConnectEvent e)
        {
            if (!e.IsTcp) return;
            string svc = ServiceFor(e.Pid, e.Image);
            if (svc == null) return;

            string blockedBy = "";
            lock (_blockedByIp)
                if (_blockedByIp.TryGetValue(e.DestIp, out var owner)) blockedBy = owner;

            AddOrUpdate(new TrackRow
            {
                TimeUtc = e.TimeUtc == default ? DateTime.UtcNow : e.TimeUtc,
                Service = svc,
                Pid = e.Pid,
                RemoteIp = e.DestIp,
                RemotePort = e.DestPort,
                State = blockedBy.Length > 0 ? "Blocked" : "Attempt",
                Class = IpClassification.Classify(e.DestIp),
                BlockedBy = blockedBy,
                Hostname = "",
            }, isAttempt: true);
        }

        private void PollEstablished()
        {
            try
            {
                foreach (var r in TcpConnectionTable.GetEstablished())
                {
                    string svc = ServiceFor(r.Pid);
                    if (svc == null) continue;
                    string blockedBy = "";
                    lock (_blockedByIp)
                        if (_blockedByIp.TryGetValue(r.RemoteIp, out var owner)) blockedBy = owner;
                    AddOrUpdate(new TrackRow
                    {
                        TimeUtc = DateTime.UtcNow,
                        Service = svc,
                        Pid = r.Pid,
                        RemoteIp = r.RemoteIp,
                        RemotePort = r.RemotePort,
                        State = "Established",
                        Class = IpClassification.Classify(r.RemoteIp),
                        BlockedBy = blockedBy,
                        Hostname = "",
                    }, isAttempt: false);
                }
            }
            catch { /* table read raced a connect teardown — next tick retries */ }
        }

        private void AddOrUpdate(TrackRow row, bool isAttempt)
        {
            // dedupe on (pid, endpoint): an established row outranks an
            // attempt for the same pair; otherwise refresh time/state in place
            for (int i = 0; i < _rows.Count; i++)
            {
                var r = _rows[i];
                if (r.Pid == row.Pid && r.RemoteIp == row.RemoteIp && r.RemotePort == row.RemotePort)
                {
                    if (!isAttempt) { _rows[i] = row; }
                    else if (string.IsNullOrEmpty(r.Hostname) && !string.IsNullOrEmpty(row.Hostname)) r.Hostname = row.Hostname;
                    return;
                }
            }
            if (!PassesFilter(row)) return;
            _rows.Insert(0, row);
            if (_rows.Count > 600) _rows.RemoveAt(_rows.Count - 1);
        }

        // ── chips + filters ────────────────────────────────────────────────

        private void BuildChips()
        {
            foreach (var s in _trackedServices.OrderBy(s => s)) AddChip(s);
        }

        private void AddChip(string service)
        {
            foreach (var (k, _) in _chips) if (k == service) return;
            var btn = new ToggleButton
            {
                Content = service,
                IsChecked = true,
                MinWidth = 90,
                Padding = new Thickness(10, 2, 10, 2),
                FontSize = 11,
            };
            btn.Checked += (_, _) => Refilter();
            btn.Unchecked += (_, _) => Refilter();
            _chips.Add((service, btn));
            ServiceChips.Children.Add(btn);
        }

        private bool ServiceEnabled(string service)
        {
            foreach (var (k, b) in _chips)
                if (k == service) return b.IsChecked == true;
            return true;
        }

        private bool PassesFilter(TrackRow r) =>
            ServiceEnabled(r.Service) &&
            (BlockedOnlyCheck.IsChecked != true || r.State == "Blocked");

        private void Refilter()
        {
            var keep = _rows.Where(PassesFilter).ToList();
            _rows.Clear();
            foreach (var r in keep) _rows.Add(r);
        }

        private void Filter_Changed(object sender, RoutedEventArgs e) => Refilter();

        private void PauseBtn_Click(object sender, RoutedEventArgs e)
        {
            _paused = !_paused;
            if (_paused) { _poll.Stop(); PauseBtn.Content = "▶ Resume"; }
            else { _poll.Start(); PauseBtn.Content = "⏸ Pause"; }
        }

        private void RefreshBlocks_Click(object sender, RoutedEventArgs e) => _ = RefreshBlocksAsync();
    }
}
