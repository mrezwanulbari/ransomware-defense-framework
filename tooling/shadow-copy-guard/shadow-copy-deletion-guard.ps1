<#
.SYNOPSIS
    shadow-copy-deletion-guard.ps1 — Behavioral prevention control that
    intercepts and blocks shadow-copy/backup-catalog deletion commands
    before they complete.

.DESCRIPTION
    Design inspired by the open-source concept pioneered by Raccine
    (https://github.com/Neo23x0/Raccine) — using process-creation
    monitoring to catch and kill the specific command patterns ransomware
    uses to delete local recovery points before encryption, rather than
    trying to detect the encryption itself. This is an original
    implementation for this repository, not a copy of Raccine's code, and
    Raccine remains the more mature, actively-maintained option — see
    resources/related-open-source-tools.md.

    This directly operationalizes the highest-priority indicator documented
    in detection/behavioral-indicators.md: shadow copy deletion is the
    single highest-value early-warning signal because it typically
    precedes mass encryption by seconds, not minutes.

    Mechanism: registers a Scheduled Task triggered on Sysmon Event ID 1
    (process creation) or Windows Security Event ID 4688, filtered to the
    specific command patterns below, which immediately terminates the
    matching process.

.NOTES
    TESTING STATUS: Written and syntax-reviewed against documented Windows
    Task Scheduler / Event Log behavior, but NOT execution-tested (no
    Windows environment available in this repository's build process).
    Validate thoroughly in a lab environment before any production
    deployment — a behavioral blocking control is exactly the kind of
    thing that needs real-environment testing before it runs where a false
    positive could block a legitimate backup administrator's actions.

    This is a PREVENTION control, not a replacement for detection/response.
    Sophisticated ransomware may use API-level shadow copy deletion (e.g.
    via IVssBackupComponents COM interface) rather than the command-line
    tools this script watches for — pair with EDR behavioral detection,
    not as a sole control.

.EXAMPLE
    .\shadow-copy-deletion-guard.ps1 -Install
    .\shadow-copy-deletion-guard.ps1 -Uninstall
#>

param(
    [switch]$Install,
    [switch]$Uninstall
)

# Command patterns that indicate shadow copy / backup catalog deletion —
# the precursor pattern documented in detection/behavioral-indicators.md
$BlockedPatterns = @(
    '*vssadmin*delete*shadows*',
    '*wmic*shadowcopy*delete*',
    '*wbadmin*delete*catalog*',
    '*bcdedit*recoveryenabled*no*',
    '*bcdedit*bootstatuspolicy*ignoreallfailures*'
)

$TaskName = "ShadowCopyDeletionGuard"

function Install-Guard {
    Write-Host "Installing shadow copy deletion guard..."

    # Requires Sysmon or Security auditing configured to log process
    # creation (Event ID 4688) with command-line auditing enabled —
    # verify this is configured before relying on this control.
    $auditPolicy = auditpol /get /subcategory:"Process Creation" 2>$null
    if ($auditPolicy -notmatch "Success") {
        Write-Warning "Process Creation auditing does not appear to be enabled. This guard depends on Event ID 4688 with command-line logging. Enable via: auditpol /set /subcategory:'Process Creation' /success:enable, and ensure 'Include command line in process creation events' is enabled via Group Policy."
    }

    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-NoProfile -WindowStyle Hidden -File `"$PSScriptRoot\block-matching-process.ps1`""

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date)
    $trigger.Subscription = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4688)]] and *[EventData[Data[@Name='CommandLine']]]</Select>
  </Query>
</QueryList>
"@

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances Parallel

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force

    Write-Host "Guard installed as scheduled task '$TaskName'."
    Write-Host "Blocked command patterns:"
    $BlockedPatterns | ForEach-Object { Write-Host "  - $_" }
}

function Uninstall-Guard {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Guard uninstalled."
}

function Test-CommandLineMatch {
    param([string]$CommandLine)
    foreach ($pattern in $BlockedPatterns) {
        if ($CommandLine -like $pattern) {
            return $true
        }
    }
    return $false
}

# --- block-matching-process.ps1 companion logic (invoked by the scheduled task) ---
# This block is what actually runs on each trigger firing: inspect the
# most recent 4688 event, and if the command line matches a blocked
# pattern, immediately terminate the process.
function Invoke-BlockCheck {
    $event = Get-WinEvent -LogName Security -MaxEvents 1 -FilterXPath "*[System[(EventID=4688)]]"
    if (-not $event) { return }

    $xml = [xml]$event.ToXml()
    $commandLine = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "CommandLine" }).'#text'
    $newProcessId = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq "NewProcessId" }).'#text'

    if (Test-CommandLineMatch -CommandLine $commandLine) {
        $pid = [Convert]::ToInt32($newProcessId, 16)
        Write-Warning "BLOCKED: Terminating PID $pid — command line matched shadow-copy-deletion pattern: $commandLine"
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue

        # Log the block event for correlation with SIEM
        $logEntry = "$(Get-Date -Format o) BLOCKED PID=$pid CommandLine=`"$commandLine`""
        Add-Content -Path "$env:ProgramData\ShadowCopyGuard\block-log.txt" -Value $logEntry -Force
    }
}

if ($Install) {
    Install-Guard
} elseif ($Uninstall) {
    Uninstall-Guard
} else {
    Write-Host "Specify -Install or -Uninstall. See script header for full documentation."
}
