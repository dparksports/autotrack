using System.Linq;
using Microsoft.UI.Xaml;

namespace AutoTrack
{
    public partial class App : Application
    {
        public static MainWindow MainWin { get; private set; }

        public App()
        {
            InitializeComponent();
            UnhandledException += (s, args) =>
            {
                try
                {
                    System.IO.File.AppendAllText(
                        System.IO.Path.Combine(System.AppDomain.CurrentDomain.BaseDirectory, "crash.log"),
                        $"\n[{System.DateTime.Now:yyyy-MM-dd HH:mm:ss}] {args.Exception}\n");
                }
                catch { }
                args.Handled = true;
            };
        }

        protected override void OnLaunched(LaunchActivatedEventArgs args)
        {
            MainWin = new MainWindow();
            MainWin.Activate();

            // UI self-test: auto-run in the SMOKE build (the release gate
            // launches that variant and refuses to ship without PASS), or on
            // demand with --selftest. One layout pass first so panes realize.
#if SMOKE
            const bool autoSelfTest = true;
#else
            const bool autoSelfTest = false;
#endif
            bool wanted = autoSelfTest || Environment.GetCommandLineArgs()
                .Any(a => a.Equals("--selftest", StringComparison.OrdinalIgnoreCase));
            if (!wanted) return;
            var t = Microsoft.UI.Dispatching.DispatcherQueue.GetForCurrentThread().CreateTimer();
            t.Interval = TimeSpan.FromSeconds(4);
            t.Tick += (_, _) =>
            {
                var (pass, detail) = SelfTest.Run(MainWin);
                Environment.Exit(SelfTest.WriteResult(pass, detail));
            };
            t.Start();
        }
    }
}
