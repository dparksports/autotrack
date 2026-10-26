using System;
using System.Collections.Generic;
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
using AutoTrack.Services;

namespace AutoTrack.Views
{
    /// <summary>
    /// Trace ANY process instance: pick a running process (or right-click a
    /// tracker row → Trace this process), and this page assembles the facts —
    /// identity card (verified spawn chain, task attribution, svchost decode),
    /// every Sysmon connect attempt incl. firewall-dropped ones, live
    /// established connections, and a destinations rollup with cadence
    /// regularity. Block actions on any destination create AT-BLOCK rules
    /// (same flow as the tracker tab). Traces are session-scoped.
    /// Byte counts are deliberately absent: Sysmon carries no payload sizes
    /// and honest volume needs the raw-capture stack this lean app omits.
    /// </summary>
    public sealed partial class TraceView : Page
    {
        private sealed class Trace
        {
            public int Pid;
            public string Exe;
            public string Display;          // chip label
            public ToggleButton Btn;
            public bool Exited;
            public DateTime? ExitedAtUtc;
            public readonly List<ConnFact> Facts = new(); // pid+ip+port+time+blocked
        }

        private sealed class ConnFact
        {
            public DateTime TsUtc;
            public string Ip;
            public int Port;
            public bool Blocked;   // was the attempt dropped by a block rule
            public bool Established;
        }

        private readonly DispatcherQueue _dq;
        private readonly DispatcherQueueTimer _poll;
        private readonly List<Trace> _traces = new();
        private Trace _current;
        private readonly Dictionary<string, string> _blockedByIp = new(StringComparer.OrdinalIgnoreCase);

        public TraceView()
        {
            InitializeComponent();
            _dq = DispatcherQueue.GetForCurrentThread();
            _poll = _dq.CreateTimer();
            _poll.Interval = TimeSpan.FromSeconds(5);
            _poll.Tick += (_, _) => PollLive();
            _poll.Start();
        }

        // ── public entries ────────────────────────────────────────────────

        /// <summary>Shared blocked-IP map from the tracker tab (owner-labeled).</summary>
        public void UpdateBlockedMap(Dictionary<string, string> map)
        {
            lock (_blockedByIp)
            {
                _blockedByIp.Clear();
                foreach (var kv in map) _blockedByIp[kv.Key] = kv.Value;
            }
            if (_current != null) RenderDestinations();
        }

        public void TracePid(int pid)
        {
            var t = StartTrace(pid);
            if (t != null) Select(t);
        }

        // ── picker ────────────────────────────────────────────────────────

        private sealed class ProcRow
        {
            public int Pid; public string Name; public string Display;
            public bool Tracked; public string TrackedService;
            public string TrackedVisibility;
            public override string ToString() => Display;
        }

        private async void PickProcess_Click(object sender, RoutedEventArgs e)
        {
            _pickerFilter = "All";
            var list = new ListView { MaxHeight = 420, MinWidth = 480,
                FontSize = 12, ItemTemplate = ProcRowTemplate() };
            ApplyPickerSource(list, "");
            var search = new TextBox { PlaceholderText = "filter (e.g. svchost, msedge, python)" };
            var filterAll = new RadioButton { Content = "All", IsChecked = true, Tag = "All" };
            var filterTracked = new RadioButton { Content = "Tracked", Tag = "Tracked" };
            var filterUntracked = new RadioButton { Content = "Untracked", Tag = "Untracked" };
            var filterRow = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12 };
            filterRow.Children.Add(filterAll);
            filterRow.Children.Add(filterTracked);
            filterRow.Children.Add(filterUntracked);
            foreach (var rb in new[] { filterAll, filterTracked, filterUntracked })
                rb.Checked += (_, _) => { _pickerFilter = rb.Tag as string; ApplyPickerSource(list, search.Text); };
            var panel = new StackPanel { Spacing = 8, MinWidth = 500 };
            panel.Children.Add(search);
            panel.Children.Add(filterRow);
            panel.Children.Add(list);
            search.TextChanged += (_, _) => ApplyPickerSource(list, search.Text);

            var dlg = new ContentDialog
            {
                Title = "Trace which process instance?",
                Content = panel,
                PrimaryButtonText = "Trace",
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = App.MainWin?.Content?.XamlRoot,
            };
            if (await dlg.ShowAsync() == ContentDialogResult.Primary && list.SelectedItem is ProcRow pr)
                TracePid(pr.Pid);
        }

        private string _pickerFilter = "All";

        /// <summary>Is this instance one of the tracked services? The app's
        /// tracked set lives in MainWindow — exposed via a static hook so the
        /// picker badges and the grid agree on one definition.</summary>
        internal static Func<int, string, string> TrackedServiceFor =
            (_, _) => null;   // MainWindow overwrites at startup

        private bool RowPassesFilter(ProcRow p) =>
            _pickerFilter switch
            {
                "Tracked" => p.Tracked,
                "Untracked" => !p.Tracked,
                _ => true,
            };

        private void ApplyPickerSource(ListView list, string query)
        {
            var q = (query ?? "").Trim();
            var rows = ProcRows()
                .Where(p => string.IsNullOrEmpty(q) || p.Display.Contains(q, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(p => p.Tracked)
                .ToList();
            list.ItemsSource = rows.Where(RowPassesFilter).ToList();
        }

        /// <summary>Row: pid (secondary) · name — with a #007AFF 'tracked'
        /// pill when the instance belongs to a tracked service.</summary>
        private static DataTemplate ProcRowTemplate() =>
            (DataTemplate)Microsoft.UI.Xaml.Markup.XamlBindingHelper.ConvertValue(
                typeof(DataTemplate), null) is null ? null : MakeRowTemplate();

        private static DataTemplate MakeRowTemplate()
        {
            // built in code: XamlReader needs a string; keep it small
            string xaml = "<DataTemplate xmlns=\"http://schemas.microsoft.com/winfx/2006/xaml/presentation\">" +
                "<StackPanel Orientation=\"Horizontal\" Spacing=\"8\">" +
                  "<TextBlock Text=\"{Binding Pid}\" FontFamily=\"Consolas\" Foreground=\"#86868B\" " +
                    "VerticalAlignment=\"Center\" Width=\"52\"/>" +
                  "<TextBlock Text=\"{Binding Name}\" VerticalAlignment=\"Center\"/>" +
                  "<Border Background=\"#E5F1FF\" CornerRadius=\"8\" Padding=\"8,1\" " +
                    "Visibility=\"{Binding TrackedVisibility}\" VerticalAlignment=\"Center\">" +
                    "<TextBlock Text=\"{Binding TrackedService}\" FontSize=\"11\" Foreground=\"#007AFF\"/>" +
                  "</Border>" +
                "</StackPanel></DataTemplate>";
            return (DataTemplate)Microsoft.UI.Xaml.Markup.XamlReader.Load(xaml);
        }

        private static List<ProcRow> ProcRows()
        {
            var rows = new List<ProcRow>();
            foreach (var p in Process.GetProcesses().OrderBy(p => p.ProcessName))
            {
                var row = new ProcRow { Pid = p.Id, Name = p.ProcessName };
                row.Display = $"{row.Pid,6}  {row.Name}";
                if (row.Name.Equals("svchost", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var id = SvchostIdentityService.Resolve(row.Pid);
                        if (id != null && !string.IsNullOrEmpty(id.DeclaredService))
                            row.Display += $"   → {id.DeclaredService}";
                        else if (id != null && !string.IsNullOrEmpty(id.Group))
                            row.Display += $"   → -k {id.Group}";
                    }
                    catch { }
                }
                row.TrackedService = TrackedServiceFor?.Invoke(row.Pid, row.Name);
                row.Tracked = !string.IsNullOrEmpty(row.TrackedService);
                if (row.Tracked) row.Display += $"   [tracked: {row.TrackedService}]";
                row.TrackedVisibility = row.Tracked ? "Visible" : "Collapsed";
                rows.Add(row);
            }
            return rows;
        }

        // ── trace lifecycle ───────────────────────────────────────────────

        private Trace StartTrace(int pid)
        {
            var existing = _traces.FirstOrDefault(t => t.Pid == pid);
            if (existing != null) return existing;

            string exe = null;
            try { using var p = Process.GetProcessById(pid); exe = p.ProcessName; }
            catch
            {
                StatusText.Text = $"pid {pid} already exited — tracing its archive history";
            }
            if (exe == null) exe = "?";

            var t = new Trace { Pid = pid, Exe = exe };
            // chip label: svchost decoded so chips read "the diagtrack one"
            if (exe.Equals("svchost", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    var id = SvchostIdentityService.Resolve(pid);
                    t.Display = id?.DeclaredService is string s && s.Length > 0 ? $"svchost:{s}" : $"svchost:{pid}";
                }
                catch { t.Display = $"svchost:{pid}"; }
            }
            else t.Display = $"{exe}:{pid}";

            var btn = new ToggleButton { Content = "🔍 " + t.Display, MinWidth = 110, FontSize = 11, Padding = new Thickness(10, 2, 10, 2) };
            btn.Checked += (_, _) => Select(t);
            btn.Unchecked += (_, _) => { if (_current == t) { _current = null; DetailPane.Visibility = Visibility.Collapsed; IdentityCard.Visibility = Visibility.Collapsed; } };
            t.Btn = btn;
            _traces.Add(t);
            TraceChips.Children.Add(btn);
            LoadHistory(t);
            return t;
        }

        private void Select(Trace t)
        {
            foreach (var x in _traces) x.Btn.IsChecked = x == t;
            _current = t;
            IdentityCard.Visibility = Visibility.Visible;
            DetailPane.Visibility = Visibility.Visible;
            RenderIdentity(t);
            RenderDestinations();
            RenderHistory(t);
        }

        // ── identity card ────────────────────────────────────────────────

        private void RenderIdentity(Trace t)
        {
            IdTitle.Text = $"{t.Display}  ·  pid {t.Pid}" + (t.Exited ? $"  — exited {(t.ExitedAtUtc?.ToLocalTime().ToString("HH:mm:ss") ?? "?")}" : "  — running");
            try
            {
                var rep = ProcessProvenanceService.Collect(t.Pid, t.Exe == "?" ? null : t.Exe + ".exe");
                IdVerdict.Text = $"Verdict: {rep.Verdict} — {rep.VerdictDetail}";
                var chain = string.Join("  ←  ", rep.Chain.Select(l =>
                    $"{l.Pid} {l.Name}{(l.Verified ? "" : " [UNVERIFIED]")}" +
                    (string.IsNullOrEmpty(l.Note) ? "" : $" ({l.Note})")));
                IdChain.Text = "SPAWN CHAIN: " + chain;
            }
            catch (Exception ex)
            {
                IdVerdict.Text = "identity unavailable: " + ex.Message;
                IdChain.Text = "";
            }
        }

        // ── history (Sysmon) + live (TCP table) ──────────────────────────

        private void LoadHistory(Trace t)
        {
            try
            {
                var since = DateTime.UtcNow - TimeSpan.FromDays(7);
                var events = SysmonArchiveService.SearchConnectionsByPid(t.Pid, since, 2000);
                lock (t.Facts)
                {
                    foreach (var e in events)
                    {
                        string ip = e.Data.TryGetValue("DestinationIp", out var ipv) ? ipv : null;
                        if (string.IsNullOrEmpty(ip)) continue;
                        int port = e.Data.TryGetValue("DestinationPort", out var pv) && int.TryParse(pv, out var pn) ? pn : 0;
                        bool blocked = false;
                        lock (_blockedByIp) blocked = _blockedByIp.ContainsKey(ip);
                        t.Facts.Add(new ConnFact { TsUtc = e.TsUtc, Ip = ip, Port = port, Blocked = blocked });
                    }
                }
            }
            catch { /* archive unreadable — live still works */ }
            if (t == _current) { RenderDestinations(); RenderHistory(t); }
        }

        private void PollLive()
        {
            foreach (var t in _traces)
            {
                bool alive;
                try { using var p = Process.GetProcessById(t.Pid); alive = true; }
                catch { alive = false; }
                if (!alive && !t.Exited)
                {
                    t.Exited = true;
                    t.ExitedAtUtc = DateTime.UtcNow;
                    t.Btn.Content = "🪌 " + t.Display;
                    if (t == _current) RenderIdentity(t);
                    continue;
                }
                if (alive)
                {
                    try
                    {
                        foreach (var r in TcpConnectionTable.GetEstablished())
                        {
                            if (r.Pid != t.Pid) continue;
                            lock (t.Facts)
                            {
                                if (!t.Facts.Any(f => f.Ip == r.RemoteIp && f.Port == r.RemotePort && f.Established))
                                    t.Facts.Add(new ConnFact { TsUtc = DateTime.UtcNow, Ip = r.RemoteIp, Port = r.RemotePort, Established = true });
                            }
                        }
                    }
                    catch { }
                }
            }
            if (_current != null) RenderDestinations();
        }

        // ── rendering ────────────────────────────────────────────────────

        private sealed class DestRow
        {
            public string Ip; public int Count; public DateTime First, Last;
            public bool AnyBlocked; public string Class;
            public double Cv; // inter-arrival coefficient of variation
        }

        private List<DestRow> Destinations(Trace t)
        {
            lock (t.Facts)
            {
                var rows = t.Facts.GroupBy(f => f.Ip, StringComparer.OrdinalIgnoreCase)
                    .Select(g =>
                    {
                        var times = g.Select(f => f.TsUtc).OrderBy(x => x).ToList();
                        double cv = 0;
                        if (times.Count >= 3)
                        {
                            var gaps = times.Zip(times.Skip(1), (a, b) => (b - a).TotalSeconds).ToList();
                            double mean = gaps.Average();
                            if (mean > 0)
                            {
                                double sd = Math.Sqrt(gaps.Sum(x => (x - mean) * (x - mean)) / gaps.Count);
                                cv = sd / mean;
                            }
                        }
                        return new DestRow
                        {
                            Ip = g.Key,
                            Count = g.Count(),
                            First = times[0],
                            Last = times[^1],
                            AnyBlocked = g.Any(f => f.Blocked),
                            Class = IpClassification.Classify(g.Key),
                            Cv = cv,
                        };
                    })
                    .OrderByDescending(r => r.Last)
                    .ToList();
                return rows;
            }
        }

        private void RenderDestinations()
        {
            var t = _current; if (t == null) return;
            DestList.Children.Clear();
            foreach (var d in Destinations(t).Take(60))
            {
                string blockedMark = "";
                lock (_blockedByIp)
                    if (_blockedByIp.TryGetValue(d.Ip, out var owner)) blockedMark = $"  ⛔ {owner}";
                string cadence = d.Count >= 3 && d.Cv > 0 && d.Cv < 0.35 ? "  ⏱ metronomic" : "";
                var tb = new TextBlock
                {
                    Text = $"{d.Ip,-16} ×{d.Count,-4} {d.Class}{cadence}{blockedMark}",
                    FontFamily = new FontFamily("Consolas"),
                    FontSize = 12,
                    Foreground = d.AnyBlocked || blockedMark.Length > 0
                        ? (Brush)Application.Current.Resources["AccentRedBrush"]
                        : (Brush)Application.Current.Resources["TextPrimaryBrush"],
                    Tag = d.Ip,
                };
                tb.RightTapped += (s, e) =>
                {
                    var menu = new MenuFlyout();
                    var block = new MenuFlyoutItem { Text = "⛔ Block this address" };
                    block.Click += async (_, _) =>
                    {
                        await TrackEnv.Fw.AddIpBlockAsync((string)((TextBlock)s).Tag,
                            $"{_current.Display}/{(string)((TextBlock)s).Tag} (AutoTrack)");
                        StatusText.Text = "blocked " + (string)((TextBlock)s).Tag;
                    };
                    menu.Items.Add(block);
                    menu.ShowAt((FrameworkElement)s, e.GetPosition((FrameworkElement)s));
                    e.Handled = true;
                };
                DestList.Children.Add(tb);
            }
            StatusText.Text = $"{t.Display}: {t.Facts.Count} connection facts · {Destinations(t).Count} destinations";
        }

        private void RenderHistory(Trace t)
        {
            HistoryList.Children.Clear();
            lock (t.Facts)
            {
                foreach (var f in t.Facts.OrderByDescending(x => x.TsUtc).Take(150))
                {
                    HistoryList.Children.Add(new TextBlock
                    {
                        Text = $"{f.TsUtc.ToLocalTime():MM-dd HH:mm:ss}  {f.Ip}:{f.Port}" +
                               (f.Blocked ? "  ⛔ blocked" : f.Established ? "  ✔ live" : "  · attempt"),
                        FontFamily = new FontFamily("Consolas"),
                        FontSize = 11,
                        Foreground = f.Blocked
                            ? (Brush)Application.Current.Resources["AccentRedBrush"]
                            : (Brush)Application.Current.Resources["TextSecondaryBrush"],
                    });
                }
            }
        }
    }
}
