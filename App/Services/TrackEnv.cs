using System;
using AutoScope.Engines.Firewall;
using Microsoft.FSharp.Collections;

namespace AutoTrack.Services
{
    /// <summary>
    /// The app's composed firewall engine instance, held where any view can
    /// reach it — the WinUI port of AutoCommand's FirewallService.Instance
    /// singleton. Constructed with the SAME naming MainWindow composes
    /// (AT-BLOCK prefixes, ADOPTING both AutoCommand's and AutoScope's block
    /// rules, "AutoTrack User Block" provenance marker). Its own instance on
    /// purpose: the engine is a stateless naming record + COM calls, so a
    /// second composition with identical naming is harmless, and MainWindow
    /// stays untouched.
    /// </summary>
    public static class TrackEnv
    {
        public static FirewallService Fw { get; } = Create();

        private static FirewallService Create()
        {
            var adoptBoth = ListModule.OfArray(
                new[] { "AC-BLOCK-IP ", "AC-BLOCK-APP ", "AS-BLOCK-IP ", "AS-BLOCK-APP " });
            var naming = new FirewallNaming(
                "AT-BLOCK-IP ", "AT-BLOCK-APP ", adoptBoth,
                ListModule.Empty<string>(),
                ListModule.Empty<string>(), "AutoTrack User Block");
            return new FirewallService(naming);
        }
    }
}
