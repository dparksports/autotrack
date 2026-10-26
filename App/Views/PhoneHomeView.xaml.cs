using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AutoTrack.Services;
using AutoScope.Engines.Core;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.UI;

namespace AutoTrack.Views
{
    /// <summary>
    /// "What are Windows' own services doing on the network?" — one card per
    /// curated talker (DiagTrack, CryptSvc, Delivery Optimization…): the
    /// authored plain-English story, the measured connect frequency against
    /// the authored normal band, destinations, beacon regularity and identity
    /// corroboration, all from TraceMetricsService. Every card can block its
    /// measured destinations through the standard confirm flow, and the
    /// impact chip says what breaking the service would cost.
    /// WinUI port: the DiagTrack "quiet it" hosts pin with sinkhole receipts
    /// is AutoCommand's surface (SinkholeService listens on 127.0.0.1,
    /// TelemetryProofService turns denied attempts into receipts) — none of
    /// that is in this build, so the quiet surface is a collapsed stub and
    /// destination blocks run through the app's composed firewall engine
    /// (TrackEnv.Fw) instead of AutoCommand's singleton.
    /// </summary>
    public sealed partial class PhoneHomeView : Page
    {
        private readonly DispatcherQueue _dq;
        private readonly DispatcherQueueTimer _timer; // WinUI port: DispatcherTimer → DispatcherQueueTimer
        private bool _refreshing;

        public PhoneHomeView()
        {
            InitializeComponent();
            _dq = DispatcherQueue.GetForCurrentThread();
            _timer = _dq.CreateTimer();
            _timer.Interval = TimeSpan.FromSeconds(60);
            _timer.Tick += (_, _) => Refresh();
            _timer.Start();
            Loaded += (_, _) => Refresh();

            // WinUI port: the WPF row DataTriggers (verdict dot fill) and the
            // BoolToVis converter don't exist here — rows are configured from
            // their VM in code-behind as containers are (re)realized. This
            // covers container recycling, which a one-shot Loaded handler
            // would miss when ItemsSource is replaced on each refresh.
            RowList.ContainerContentChanging += (sender, args) =>
            {
                if (args.InRecycleQueue) return;
                if (args.Item is TraceMetricsService.TraceCardVM vm &&
                    args.ItemContainer?.ContentTemplateRoot is FrameworkElement root)
                    ConfigureRow(root, vm);
            };
        }

        // ── refresh ──────────────────────────────────────────────────────

        private void Refresh()
        {
            if (_refreshing) return;
            _refreshing = true;
            StatusText.Text = "Reading the archive…";
            _ = Task.Run(() =>
            {
                var vms = new List<TraceMetricsService.TraceCardVM>();
                foreach (var key in TraceMetricsService.CuratedPhoneHomeKeys)
                {
                    try
                    {
                        var snap = TraceMetricsService.Compute(TraceMetricsService.Match.ForService(key));
                        var vm = TraceMetricsService.BuildCardVM(snap);
                        // WinUI port: CanQuiet/IsQuieted drove AutoCommand's
                        // DiagTrack hosts pin (DiagTrackPin + SinkholeService
                        // receipts) — not in this build, so they stay false
                        // and the quiet section in the detail pane is a
                        // collapsed stub.
                        vms.Add(vm);
                    }
                    catch { /* one bad card must not take the tab down */ }
                }
                vms.Sort((a, b) => b.ConnectsPerHour.CompareTo(a.ConnectsPerHour));
                _dq.TryEnqueue(() => // WinUI port: Dispatcher.BeginInvoke → TryEnqueue
                {
                    // keep the user's selection stable across refreshes —
                    // same service, same row, even as sorting reorders them
                    var selectedKey = (RowList.SelectedItem as TraceMetricsService.TraceCardVM)?.ServiceKey;
                    RowList.ItemsSource = vms;
                    var restore = vms.FirstOrDefault(v => v.ServiceKey == selectedKey) ?? vms.FirstOrDefault();
                    RowList.SelectedItem = restore; // SelectionChanged → UpdateDetail
                    if (restore == null) UpdateDetail(null);
                    StatusText.Text = $"Updated {DateTime.Now:HH:mm:ss} · rows sorted by measured connects/hr · refresh 60 s";
                    _refreshing = false;
                });
            });
        }

        // ── row visuals (WinUI port of the WPF DataTriggers) ─────────────

        private static void ConfigureRow(FrameworkElement root, TraceMetricsService.TraceCardVM vm)
        {
            if (FindChild<Ellipse>(root, "VerdictDot") is { } dot)
                dot.Fill = vm.VerdictKind switch
                {
                    "normal" => DotNormal,
                    "elevated" => DotElevated,
                    _ => DotUnknown,
                };
            if (FindChild<TextBlock>(root, "QuietMark") is { } quiet)
                quiet.Visibility = vm.IsQuieted ? Visibility.Visible : Visibility.Collapsed;
            if (FindChild<TextBlock>(root, "BeaconMark") is { } beacon)
                beacon.Visibility = vm.BeaconRegular ? Visibility.Visible : Visibility.Collapsed;
        }

        // name lookup inside an inflated DataTemplate (names there are not
        // reachable via this.FindName)
        private static T FindChild<T>(DependencyObject root, string name) where T : FrameworkElement
        {
            int n = VisualTreeHelper.GetChildrenCount(root);
            for (int i = 0; i < n; i++)
            {
                var child = VisualTreeHelper.GetChild(root, i);
                if (child is T hit && hit.Name == name) return hit;
                var deeper = FindChild<T>(child, name);
                if (deeper != null) return deeper;
            }
            return null;
        }

        // ── detail pane (WinUI port: no SelectedItem ElementName binding and
        //    no converters — every element is named and set from code-behind;
        //    VMs are immutable per refresh, so this runs on selection only) ─

        private void RowList_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
            UpdateDetail(RowList.SelectedItem as TraceMetricsService.TraceCardVM);

        private void UpdateDetail(TraceMetricsService.TraceCardVM vm)
        {
            if (vm == null)
            {
                DetailScroll.Visibility = Visibility.Collapsed;
                NoSelectionHint.Visibility = Visibility.Visible;
                return;
            }
            DetailScroll.Visibility = Visibility.Visible;
            NoSelectionHint.Visibility = Visibility.Collapsed;

            TitleText.Text = vm.Title;
            ChipProcessText.Text = vm.ChipProcess;
            ImpactChipText.Text = vm.ChipImpact;
            ImpactChip.Background = vm.ChipImpactKind switch
            {
                "high" => ImpactHighBg,
                "medium" => ChipElevatedBg,
                "normal" => ChipNormalBg,
                _ => ImpactDefaultBg,
            };

            VerdictChipText.Text = vm.VerdictText;
            VerdictChip.Background = vm.VerdictKind switch
            {
                "normal" => ChipNormalBg,
                "elevated" => ChipElevatedBg,
                _ => ChipUnknownBg,
            };
            VerdictChip.BorderBrush = vm.VerdictKind switch
            {
                "normal" => GreenBorder,
                "elevated" => AmberBorder,
                _ => ChipUnknownBorder,
            };

            StoryText.Text = vm.Story;
            BarsList.ItemsSource = vm.Bars;
            MetricsText.Text = vm.MetricsLine;
            BytesText.Text = vm.BytesLine;

            DestList.ItemsSource = vm.Destinations;
            NoDestsHint.Visibility = vm.Destinations.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

            BeaconText.Text = vm.BeaconLine;
            IdentityText.Text = vm.IdentityLine;
            ReceiptsText.Text = vm.ReceiptsLine;
            ReceiptsText.Visibility = string.IsNullOrEmpty(vm.ReceiptsLine)
                ? Visibility.Collapsed : Visibility.Visible;
            FootnoteText.Text = vm.Footnote;
        }

        // WinUI port: the WPF DataTrigger palettes as code-behind brush tables
        private static readonly SolidColorBrush DotNormal = Brush(0xFF, 0x34, 0xD3, 0x99);
        private static readonly SolidColorBrush DotElevated = Brush(0xFF, 0xFB, 0xBF, 0x24);
        private static readonly SolidColorBrush DotUnknown = Brush(0xFF, 0x98, 0xA2, 0xB3);
        private static readonly SolidColorBrush ChipNormalBg = Brush(0x33, 0x34, 0xD3, 0x99);
        private static readonly SolidColorBrush ChipElevatedBg = Brush(0x33, 0xFB, 0xBF, 0x24);
        private static readonly SolidColorBrush ChipUnknownBg = Brush(0x33, 0x98, 0xA2, 0xB3);
        private static readonly SolidColorBrush ChipUnknownBorder = Brush(0xFF, 0x39, 0x41, 0x4F); // theme BorderColor
        private static readonly SolidColorBrush GreenBorder = Brush(0xFF, 0x34, 0xD3, 0x99);
        private static readonly SolidColorBrush AmberBorder = Brush(0xFF, 0xFB, 0xBF, 0x24);
        private static readonly SolidColorBrush ImpactHighBg = Brush(0x33, 0xF8, 0x71, 0x71);
        private static readonly SolidColorBrush ImpactDefaultBg = Brush(0x14, 0xFF, 0xFF, 0xFF);

        private static SolidColorBrush Brush(byte a, byte r, byte g, byte b) => new(Color.FromArgb(a, r, g, b));

        // ── dialogs ──────────────────────────────────────────────────────

        // WinUI port: MessageBox → ContentDialog (AutoTrack's single window
        // owns the XamlRoot). AutoCommand's BlockConfirmWindow + ConfirmPrefs
        // "don't ask again" checkbox are not in this build — a plain confirm.
        private static ContentDialog NewDialog(string title, string body, string primary)
        {
            return new ContentDialog
            {
                Title = title,
                Content = new TextBlock
                {
                    Text = body,
                    TextWrapping = TextWrapping.Wrap,
                    FontSize = 13,
                    MaxWidth = 480,
                },
                PrimaryButtonText = primary,
                CloseButtonText = "Cancel",
                DefaultButton = ContentDialogButton.Primary,
                XamlRoot = App.MainWin?.Content?.XamlRoot,
            };
        }

        private static async Task ShowInfoAsync(string title, string body)
        {
            var dlg = NewDialog(title, body, "OK");
            if (dlg.XamlRoot == null) return;
            await dlg.ShowAsync();
        }

        private static async Task<bool> ConfirmAsync(string title, string body, string primary = "OK")
        {
            var dlg = NewDialog(title, body, primary);
            if (dlg.XamlRoot == null) return false;
            return await dlg.ShowAsync() == ContentDialogResult.Primary;
        }

        // ── suppression / blocks ─────────────────────────────────────────

        // WinUI port: QuietBtn_Click / UndoQuietBtn_Click and DiagTrackPin
        // (AutoCommand's hosts-pin writer) are intentionally not ported —
        // AutoTrack has no SinkholeService/TelemetryProofService, so the pin
        // could not keep its "with receipts" promise. The UI section is the
        // collapsed QuietSection stub in the XAML.

        private async void BlockBtn_Click(object sender, RoutedEventArgs e)
        {
            if ((sender as FrameworkElement)?.DataContext is not TraceMetricsService.TraceCardVM vm) return;
            var ips = vm.TopDestIps.Where(ip => !string.IsNullOrEmpty(ip)).ToList();
            if (ips.Count == 0)
            {
                await ShowInfoAsync("Block destinations",
                    "No destinations were measured for this service in the last 24 h — nothing to block yet.");
                return;
            }

            TraceMetricsService.TryGetCatalog(vm.ServiceKey, out var description, out var impactKind);
            bool risky = impactKind is "high" or "medium";
            string headline = $"Block {vm.Title}'s destinations";
            string warning = risky
                ? $"{vm.Title} is catalogued as {impactKind.ToUpper()} impact: {description}"
                : $"{vm.Title} is catalogued as safe to block: {description ?? "no catalog entry — blocking the measured destinations only"}";
            string body = warning + "\n\n" +
                "Outbound firewall rules for:\n" + string.Join("\n", ips.Select(ip => "  " + ip)) +
                "\n\nThe service can still reach other addresses; Windows Firewall blocks " +
                "silently, so expect quiet failures if this service matters.\n" +
                "Undo: delete the AT-BLOCK-IP rules in Windows Defender Firewall (wf.msc).";
            if (!await ConfirmAsync(headline, body, "Block")) return;

            int created = 0;
            try
            {
                foreach (var ip in ips)
                {
                    // WinUI port: the composed engine instance (TrackEnv —
                    // same AT-BLOCK naming MainWindow uses) replaces
                    // AutoCommand's FirewallService.Instance. There is no
                    // BlocksStore in this build; the rule Description is the
                    // provenance trail.
                    var (made, _) = await TrackEnv.Fw.AddIpBlockAsync(ip,
                        $"[blocked {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC] {vm.Title} ({vm.ServiceKey}) " +
                        $"top destination from Phone Home · AutoTrack Phone Home");
                    created += made;
                }
            }
            catch (Exception ex)
            {
                await ShowInfoAsync("Block destinations", "Block failed: " + ex.Message);
                return;
            }
            await ShowInfoAsync("Block destinations",
                created > 0 ? $"Blocked {created} destination(s) for {vm.Title}."
                            : "Rules already existed for all listed destinations — nothing new created.");
            Refresh();
        }

        /// <summary>Blocks one destination IP of the selected service — the
        /// per-row action next to each destination in the detail pane.</summary>
        private async void BlockOneBtn_Click(object sender, RoutedEventArgs e)
        {
            // WinUI port: the button carries the destination IP in Tag; the
            // card comes from the current selection (the destination item is
            // not the card VM).
            if (sender is not Button btn || string.IsNullOrEmpty(btn.Tag as string)) return;
            if (RowList.SelectedItem is not TraceMetricsService.TraceCardVM vm) return;
            string ip = (string)btn.Tag;

            TraceMetricsService.TryGetCatalog(vm.ServiceKey, out var description, out var impactKind);
            bool risky = impactKind is "high" or "medium";
            string warning = risky
                ? $"{vm.Title} is catalogued as {impactKind.ToUpper()} impact: {description}"
                : IpClassification.WarningText(ip);
            string body = (string.IsNullOrEmpty(warning) ? "" : warning + "\n\n") +
                $"Outbound firewall rules for {ip} — a measured destination of {vm.Title} ({vm.ServiceKey}).\n" +
                "Undo: delete the AT-BLOCK-IP rules in Windows Defender Firewall (wf.msc).";
            if (!await ConfirmAsync($"Block {ip}", body, "Block")) return;

            try
            {
                var (made, _) = await TrackEnv.Fw.AddIpBlockAsync(ip,
                    $"[blocked {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC] {vm.Title} ({vm.ServiceKey}) " +
                    $"destination from Phone Home · AutoTrack Phone Home");
                await ShowInfoAsync("Block destination", made > 0
                    ? $"Blocked {ip} for {vm.Title}."
                    : "A block for that destination already existed.");
            }
            catch (Exception ex)
            {
                await ShowInfoAsync("Block destination", "Block failed: " + ex.Message);
            }
            Refresh();
        }
    }
}
