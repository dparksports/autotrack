using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AutoTrack
{
    /// <summary>
    /// The UI's self-test — the shell finally joins the engines' contract
    /// ("self-tests are the gate"). Run automatically by the SMOKE build
    /// variant (release pipeline gate) or on demand with --selftest.
    /// Catches exactly the two shipped regressions: a resource key that
    /// resolves at compile time but not at runtime (v2026.10.26.4), and a
    /// startup path that dies before the window exists (v2026.10.26.2).
    /// NOTE: tools/audit.py cross-checks that every resource key referenced
    /// by any XAML appears in Keys below — extend this list when adding one.
    /// </summary>
    internal static class SelfTest
    {
        internal static readonly string[] Keys =
        {
            // theme + aliases (Theme.xaml / MenuContrast.xaml / App.xaml)
            "AccentRedBrush", "AccentGreenBrush", "AccentAmberBrush",
            "BackgroundBrush", "SurfaceBrush", "BorderBrush",
            "TextPrimaryBrush", "TextSecondaryBrush",
            "PageBackgroundBrush", "SidebarBackgroundBrush",
            "CardBackgroundBrush", "CardBorderBrush",
            "SubtleTextBrush", "PageHeaderTextBrush",
            "PageHeaderText", "Header",
            // Shields Up keys used directly by ported pages
            "AccentFillBrush", "DangerFillBrush", "HeaderSize", "PageHeaderSize",
        };

        public static (bool Pass, string Detail) Run(MainWindow win)
        {
            var problems = new List<string>();

            // 1. every referenced resource key resolves at runtime
            foreach (var k in Keys)
                if (!Application.Current.Resources.TryGetValue(k, out _))
                    problems.Add("missing resource: " + k);

            // 2. the nav actually switches panes (named elements + handlers)
            try
            {
                var cases = new (NavigationViewItem item, FrameworkElement pane, string name)[]
                {
                    (win.TrackerNavItemRef, win.TrackerPaneRef, "tracker"),
                    (win.PhoneHomeNavItemRef, win.PhoneHomePaneRef, "phone-home"),
                    (win.TraceNavItemRef, win.TracePaneRef, "trace"),
                };
                foreach (var (item, pane, name) in cases)
                {
                    win.NavView.SelectedItem = item;
                    if (pane.Visibility != Visibility.Visible)
                        problems.Add("pane did not show: " + name);
                }
                win.NavView.SelectedItem = win.TrackerNavItemRef;
            }
            catch (Exception ex) { problems.Add("nav switch threw: " + ex.Message); }

            // 3. essential named elements exist and were initialized
            if (!win.TrackGridExists) problems.Add("TrackGrid null");
            if (!win.ChipsBuilt) problems.Add("service chips empty - ctor path incomplete");
            if (win.NavView == null || win.NavView.SelectedItem == null)
                problems.Add("nav selection not set");

            return (problems.Count == 0, string.Join("; ", problems));
        }

        /// <summary>Writes the result file the release gate requires.</summary>
        public static int WriteResult(bool pass, string detail)
        {
            string path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "selftest-result.txt");
            File.WriteAllText(path, (pass ? "PASS" : "FAIL: " + detail) + Environment.NewLine);
            return pass ? 0 : 1;
        }
    }
}
