#requires -Version 5.1
<#
.SYNOPSIS
    Read-only UI Automation probe of the Cisco Secure Client login window.
    Feasibility test for the closed-loop waits task in docs/SPEED-2026-07-09.md.

.DESCRIPTION
    Answers one question: does the Cisco embedded browser (WebView2 hosted by
    acwebhelper.exe) expose the SSO page's fields to Windows UI Automation?
    If yes, the worker's fixed inter-screen delays can be replaced with
    "wait until the next screen's field actually exists" (see the spec doc).

    Every poll it snapshots the target window's UIA tree (Edit/Button/Document
    elements: control type, label, IsPassword flag), the window title, and the
    globally focused element - and logs a timestamped block whenever any of
    that changes. The change timestamps double as measurements of the real
    SSO screen-load times.

    STRICTLY READ-ONLY: types nothing, clicks nothing, never calls op, and
    never queries an element's Value pattern - so a password you type by hand
    while it watches cannot appear in the output. Element LABELS do appear
    (e.g. 'Enter password', button captions), and an M365 screen label can
    include your visible email address - the log is gitignored (*.log), but
    skim it before pasting anywhere.

.NOTES
    Run this YOURSELF in a normal terminal (Claude cannot: a background shell
    has no interactive desktop). Protocol:
      1. Start it:  .\probe-uia.ps1
      2. Initiate a VPN connect so the Cisco login window appears.
      3. Log in BY HAND at normal speed - the probe just watches.
      4. Ctrl+C when connected (or let the duration lapse), then review/paste
         probe-uia.log for analysis.
    An "(empty)" tree on every screen is also a valid result: it means the
    WebView2 does not expose fields to managed UIA and the closed-loop task
    is not feasible this way.
#>
[CmdletBinding()]
param(
    # Substring of the target window title (same default as the worker).
    [string]$TitleMatch = 'Cisco Secure Client - Login',

    # Total watch time; generous so it covers connect + all three SSO screens.
    [int]$DurationSec = 120,

    # Snapshot interval. 500ms resolves screen transitions well enough to
    # both prove field visibility and time the real page loads.
    [int]$PollMs = 500
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes

$script:LogPath = Join-Path $PSScriptRoot 'probe-uia.log'
function Write-Both {
    param([string]$Line)
    Write-Host $Line
    Add-Content -Path $script:LogPath -Value $Line -ErrorAction SilentlyContinue
}

function Get-ElementSummary {
    # One safe descriptive line for an element: type + label + flags.
    # Reads only Name (the accessibility LABEL - for password fields Chromium
    # exposes no content there) and never the Value/Text patterns.
    param([System.Windows.Automation.AutomationElement]$El)
    $c = $El.Current
    $type = $c.ControlType.ProgrammaticName -replace '^ControlType\.', ''
    $name = "$($c.Name)"
    if ($name.Length -gt 60) { $name = $name.Substring(0, 57) + '...' }
    $flags = @()
    if ($c.IsPassword)        { $flags += 'password' }
    if ($c.HasKeyboardFocus)  { $flags += 'focused' }
    $flagText = if ($flags) { ' [' + ($flags -join ',') + ']' } else { '' }
    return "$type '$name'$flagText"
}

function Get-Snapshot {
    # Build the current state as a list of lines; $null-safe throughout because
    # the window can disappear between (or during) polls when login completes.
    $lines = New-Object System.Collections.Generic.List[string]

    # -- target window: enumerate top-level windows via UIA, substring-match the
    # title (the worker's matching contract). Multiple matches would be fatal
    # for the TYPING worker; for a read-only probe, watching the first is fine.
    $root = [System.Windows.Automation.AutomationElement]::RootElement
    $tops = $root.FindAll(
        [System.Windows.Automation.TreeScope]::Children,
        [System.Windows.Automation.Condition]::TrueCondition)
    $win = $null
    foreach ($t in $tops) {
        if ("$($t.Current.Name)".IndexOf($TitleMatch, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $win = $t; break
        }
    }

    if (-not $win) {
        $lines.Add("window : (no title matching '*$TitleMatch*')")
    } else {
        $lines.Add("window : '$($win.Current.Name)'")
        # -- tree: only the element kinds that identify an SSO screen. Edit
        # (input fields, with IsPassword), Button (Next/Sign in/Verify), and
        # Document (the web page root - its presence alone proves the WebView2
        # is exposing content). Text nodes are deliberately excluded: noisy,
        # and they carry page content we don't need.
        $kinds = [System.Windows.Automation.OrCondition]::new(
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Edit),
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Button),
            [System.Windows.Automation.PropertyCondition]::new(
                [System.Windows.Automation.AutomationElement]::ControlTypeProperty,
                [System.Windows.Automation.ControlType]::Document))
        $found = $win.FindAll([System.Windows.Automation.TreeScope]::Descendants, $kinds)
        if ($found.Count -eq 0) {
            $lines.Add('tree   : (empty - no Edit/Button/Document exposed)')
        } else {
            $lines.Add("tree   : $($found.Count) element(s)" +
                $(if ($found.Count -gt 20) { ' (showing first 20)' } else { '' }))
            $shown = 0
            foreach ($el in $found) {
                if ($shown -ge 20) { break }
                $lines.Add('  ' + (Get-ElementSummary $el))
                $shown++
            }
        }
    }

    # -- focused element, wherever it is (also proves a11y is alive even if
    # the tree walk above comes back empty - a known Chromium quirk).
    try {
        $foc = [System.Windows.Automation.AutomationElement]::FocusedElement
        if ($foc) { $lines.Add('focused: ' + (Get-ElementSummary $foc)) }
    } catch {
        $lines.Add('focused: (unavailable)')
    }

    return $lines
}

# --- Watch loop: log a full block only when the state changes ---------------

Write-Both ('=== probe start {0}  (title match *{1}*, {2}s, poll {3}ms) ===' -f
    (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $TitleMatch, $DurationSec, $PollMs)
Write-Host 'Watching. Start the VPN connect and log in by hand; Ctrl+C to stop.'

$deadline = (Get-Date).AddSeconds($DurationSec)
$previous = ''
$states = 0
try {
    while ((Get-Date) -lt $deadline) {
        # A window can vanish mid-walk (login completed) - treat any UIA error
        # as a transient state, not a crash.
        try { $lines = Get-Snapshot }
        catch { $lines = @("window : (UIA error: $($_.Exception.Message))") }

        $signature = $lines -join "`n"
        if ($signature -ne $previous) {
            $states++
            $previous = $signature
            Write-Both ('{0}  --- state #{1} ---' -f (Get-Date -Format 'HH:mm:ss.fff'), $states)
            foreach ($l in $lines) { Write-Both "  $l" }
        }
        Start-Sleep -Milliseconds $PollMs
    }
} finally {
    Write-Both ('=== probe end {0}  ({1} distinct state(s); log: probe-uia.log) ===' -f
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $states)
}
