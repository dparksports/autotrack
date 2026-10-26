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
        }
    }
}
