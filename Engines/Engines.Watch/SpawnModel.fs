namespace AutoScope.Engines.Watch

open System.ComponentModel

[<AllowNullLiteral>]
type SpawnItem() as this =
    let propChanged = Event<System.ComponentModel.PropertyChangedEventHandler, System.ComponentModel.PropertyChangedEventArgs>()

    let mutable exited_ = false
    let mutable flowCount_ = 0
    let mutable hasTrace_ = false
    let mutable outcome_ = null
    let mutable verdict_ = null
    let mutable venvLauncher_ = null
    let mutable isAbsorbedLauncher_ = false
    let mutable hasPythonParent_ = false
    let mutable detailBadge_ = null

    member val TimeUtc = System.DateTime() with get, set
    member val Pid = 0 with get, set
    /// <summary>Sysmon's ProcessGuid (braces stripped) — kernel-assigned and
    /// unique for the whole boot; safer than the PID for attribution.</summary>
    member val ProcessGuid: string = null with get, set
    member val Image: string = null with get, set
    member val CommandLine: string = null with get, set
    member val ParentPid = 0 with get, set
    member val ParentImage: string = null with get, set
    member val ParentCommandLine: string = null with get, set
    member val User: string = null with get, set
    member val IntegrityLevel: string = null with get, set
    member val Hashes: string = null with get, set
    member val Source: string = null with get, set

    /// <summary>The venv launcher row this spawn was paired with; null when
    /// the spawn has no launcher in front of it.</summary>
    member this.VenvLauncher = venvLauncher_
    member this.IsAbsorbedLauncher = isAbsorbedLauncher_
    member this.HasPythonParent = hasPythonParent_

    member this.MarkAbsorbedLauncher() =
        isAbsorbedLauncher_ <- true
        this.OnPropertyChanged("Badge")

    member this.SetVenvLauncher(launcher: SpawnItem) =
        venvLauncher_ <- launcher
        this.OnPropertyChanged("Badge")

    member this.SetPythonParent() =
        hasPythonParent_ <- true
        this.OnPropertyChanged("Badge")

    /// <summary>View-set badge; python badges take precedence when present.</summary>
    member this.SetDetailBadge(badge: string) =
        detailBadge_ <- badge
        this.OnPropertyChanged("Badge")

    /// <summary>Grid badge: "venv" for a paired interpreter, "py→py" for python-spawned-python.</summary>
    member this.Badge =
        if not (isNull venvLauncher_) then "venv"
        elif hasPythonParent_ then "py→py"
        else if isNull detailBadge_ then "" else detailBadge_

    member this.SetOutcome(outcome: string) =
        outcome_ <- outcome
        this.OnPropertyChanged("OutcomeDisplay")

    /// <summary>View-set verdict from TaskLaunchInfo — Inbox / Third-party / Orphaned.</summary>
    member this.SetVerdict(verdict: string) =
        verdict_ <- verdict
        this.OnPropertyChanged("Verdict")
        this.OnPropertyChanged("VerdictBackground")
        this.OnPropertyChanged("VerdictForeground")

    member this.Exited
        with get() = exited_
        and set v = exited_ <- v; this.OnPropertyChanged("Exited"); this.OnPropertyChanged("LifeDisplay")

    member this.FlowCount
        with get() = flowCount_
        and set v = flowCount_ <- v; this.OnPropertyChanged("FlowCount")

    member this.HasTrace
        with get() = hasTrace_
        and set v = hasTrace_ <- v; this.OnPropertyChanged("HasTrace")

    member this.TimeDisplay = if this.TimeUtc = System.DateTime() then "—" else this.TimeUtc.ToLocalTime().ToString("HH:mm:ss")
    member this.ImageDisplay = if System.String.IsNullOrEmpty(this.Image) then "—" else System.IO.Path.GetFileName(this.Image)
    member this.LifeDisplay = if exited_ then "exited" else "running"
    member this.OutcomeDisplay = if isNull outcome_ then (if exited_ then "exited" else "running") else outcome_
    member this.Verdict = verdict_

    /// <summary>Chip background per verdict (color string; the view converts).</summary>
    member this.VerdictBackground =
        match verdict_ with
        | "Inbox" -> "#2E5E3E"
        | "Third-party" -> "#6B4E1A"
        | "Orphaned" -> "#6E2A2A"
        | _ -> "#2A2A33"

    /// <summary>Chip text per verdict, matched to its background.</summary>
    member this.VerdictForeground =
        match verdict_ with
        | "Inbox" -> "#7ED8A0"
        | "Orphaned" -> "#F2A0B4"
        | _ -> "#E5C77B"

    /// <summary>"PID (name)" for the parent column; "—" when no parent image.</summary>
    member this.ParentDisplay =
        if System.String.IsNullOrEmpty(this.ParentImage) then
            (if this.ParentPid > 0 then string this.ParentPid else "—")
        else $"{this.ParentPid} ({System.IO.Path.GetFileName(this.ParentImage)})"

    /// <summary>Full parent image + command line for the column tooltip.</summary>
    member this.ParentToolTip =
        if System.String.IsNullOrEmpty(this.ParentImage) && System.String.IsNullOrEmpty(this.ParentCommandLine) then null
        else
            let img = (if isNull this.ParentImage then "?" else this.ParentImage)
            let cmd = (if isNull this.ParentCommandLine then System.String.Empty else this.ParentCommandLine)
            img + System.Environment.NewLine + cmd

    /// <summary>Chip background for the badge column (venv pairs get the accent blue).</summary>
    member this.BadgeBackground = if not (isNull venvLauncher_) then "#1A4A8A" else "#2A2A33"

    member private this.OnPropertyChanged(name: string) =
        propChanged.Trigger(this, PropertyChangedEventArgs(name))

    interface System.ComponentModel.INotifyPropertyChanged with
        [<CLIEvent>]
        member this.PropertyChanged = propChanged.Publish
