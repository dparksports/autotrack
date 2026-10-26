namespace AutoScope.Engines.Core

/// <summary>Everything an engine needs to know about the app hosting it.
/// Engines are app-agnostic: the same code serves AutoCommand, AutoScope or
/// Shields Up, each constructing its own identity. No engine may embed an
/// app name, rule prefix, data path or port anywhere else.</summary>
type AppIdentity =
    { /// e.g. "AutoScope" — display and logging
      Name: string
      /// data root, e.g. %LOCALAPPDATA%\AutoScope
      DataRoot: string
      /// rule-name prefixes this app CREATES (e.g. "AS-BLOCK-IP ")
      OwnIpRulePrefix: string
      OwnAppRulePrefix: string
      /// rule-name prefixes created by other installs that this app ADOPTS
      /// (manages in place, never renames) — e.g. AutoCommand's AC-BLOCK
      AdoptedRulePrefixes: string list
      /// loopback MCP bridge port scan base
      BridgePortBase: int
      /// MCP server id written into client configs
      McpId: string }

module Identity =

    /// <summary>AutoScope's policy (see the AutoScope app).</summary>
    let autoscope () =
        { Name = "AutoScope"
          DataRoot = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "AutoScope")
          OwnIpRulePrefix = "AS-BLOCK-IP "
          OwnAppRulePrefix = "AS-BLOCK-APP "
          AdoptedRulePrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP " ]
          BridgePortBase = 47921
          McpId = "autoscope" }

    /// <summary>AutoTrack's identity: a read-only service tracker. It creates
    /// no firewall rules of its own; it ADOPTS both AutoCommand's and
    /// AutoScope's block rules to report who is being blocked.</summary>
    let autotrack () =
        { Name = "AutoTrack"
          DataRoot = System.IO.Path.Combine(
                System.Environment.GetFolderPath(System.Environment.SpecialFolder.LocalApplicationData),
                "AutoTrack")
          OwnIpRulePrefix = "AT-TRACK-IP "   // unused: this app never blocks
          OwnAppRulePrefix = "AT-TRACK-APP "
          AdoptedRulePrefixes = [ "AC-BLOCK-IP "; "AC-BLOCK-APP "; "AS-BLOCK-IP "; "AS-BLOCK-APP " ]
          BridgePortBase = 48121
          McpId = "autotrack" }
