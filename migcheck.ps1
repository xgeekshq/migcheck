<#
migcheck.ps1 - test-migration checks for a Windows VM (AVS -> Azure). Read-only.

Each check is one Def below, named exactly as column A of the Windows sheet in
"Test Migration Infrastructure Checks", in the same order. A Def has:
  Command   what is run; column C of the sheet is this, verbatim, to run by hand
  Process   turns the command's output into sorted text lines, so a diff shows only real changes
  File      the lines are written to C:\migcheck\<side>\<File>.txt
  Judge     how the summary rates that file
Defs named "Extra: ..." have no sheet row.

Put this script in C:\migcheck on the AVS VM BEFORE the recovery point you test from:
the test VM then boots with the script and the AVS results already on its disk.

  C:\migcheck\migcheck.ps1
  C:\migcheck\source\      results from the AVS VM
  C:\migcheck\target\      results from the test VM
  C:\migcheck\report.txt   full comparison

1. AVS VM (RDP, elevated prompt):
     powershell -NoProfile -ExecutionPolicy Bypass -File C:\migcheck\migcheck.ps1 source
   Then wait for a recovery point newer than the time in C:\migcheck\source\collected.txt.
   Unelevated, some tasks, shares and TLS bindings are hidden on AVS, so those checks then only
   count what is missing on Azure.
2. Test VM (portal: VM > Run command > RunPowerShellScript, or a session on the VM):
     powershell -NoProfile -ExecutionPolicy Bypass -File C:\migcheck\migcheck.ps1 target
   Collects target\, compares, prints one line per check (under Run Command's 4 KB limit).
   Inter-tier test: add -Peers 10.1.2.3:1433,app2.fqdn:443
   The last line is the verdict: RESULT ... all good, or which checks need a look.
   Without C:\migcheck\source (no access to AVS) the report is on the test VM alone: no PASS/DIFF,
   compared checks are listed as INFO, and app services on Auto that are not running FAIL.
3. Compare again only:   ... migcheck.ps1 compare
   Problems and INFO:    ... migcheck.ps1 show      (their detail, then their summary lines and the verdict)
   Detail of one check:  ... migcheck.ps1 show services      (the name after the tag in the summary)
   Run Command keeps only the last 4 KB of output, so read the report one check at a time with "show".

Summary: PASS / DIFF = compared with AVS, OK / FAIL = rule on the test VM alone, INFO = shown only.
Differences expected after the move (VMware -> Azure, isolated test network) are listed as
"~ expected" in the report and do not count as DIFF.
#>
param(
    [Parameter(Position = 0)][ValidateSet('source', 'target', 'compare', 'show')][string]$Mode,
    [Parameter(Position = 1)][string]$Name,
    [string]$Root = 'C:\migcheck',
    [string[]]$Peers
)
if (-not $Mode) { 'Usage: migcheck.ps1 source | target [-Peers host:port,...] | compare | show [check]'; exit 1 }
# powershell -File passes "a,b" as one string, not an array.
$Peers = @($Peers -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })

# Expected after the move: VMware tools go, the Azure agent comes, the Arc agent stops on an Azure VM,
# and in the isolated test VNet there is no domain controller.
$Move = 'VMware|VMTools|VGAuth|vm3dservice|vmStatsProvider|WindowsAzureGuestAgent|RdAgent|Windows Azure|himds|arcproxy|Azure Arc|Hybrid Instance|Guest Configuration|gc_|Azure Connected Machine|vmic|Hyper-V'
# No DC, and no KMS for Windows activation (Security-SPP), in the isolated test network.
# EventLog 6008: the test VM boots from a replica of a running disk, so Windows logs an unexpected shutdown.
$NoDC = 'NETLOGON|GroupPolicy|Time-Service|DNS-Client|Kerberos|Security-SPP|EventLog 6008'
# Services that start on demand (Manual, delayed or trigger start) run or not depending on the minutes
# before the snapshot, so a difference in them is listed but does not count. Plain Automatic ones count.
$OnDemand = '\|\s*(Manual|Disabled|Auto-Delayed|Auto-Trigger|Manual-Trigger)\s*\|'
$Expected = @{
    ports = $Move; services = "$Move|$OnDemand"; autostop = "$Move|$OnDemand"; tasks = $Move
    syserr = "$Move|$NoDC"; apperr = "$Move|$NoDC"
}
$PerUser = '_[0-9a-f]{4,}$'   # per-user services (name ending _1a2b3c4d) only run while someone is logged on

# Start type as services.msc shows it. Trigger start lives in the registry, not in Win32_Service.
function StartType($s) {
    $t = if ($s.StartMode -eq 'Auto') { if ($s.DelayedAutoStart) { 'Auto-Delayed' } else { 'Auto' } } else { "$($s.StartMode)" }
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\TriggerInfo") { $t = ($t -replace '-Delayed$', '') + '-Trigger' }
    $t
}
# One service per line, in aligned columns, the category first so the file sorts into groups:
#   AGENT  monitoring, security or management tools (known vendors below)
#   APP?   not Windows and not a known agent: most likely the application; the app owner confirms
#   WIN    a program under C:\Windows
#   ?      path hidden (without admin, for some protected services)
# Only the service name is compared (-KeyField 1): without admin the start type, path and company of
# some services are hidden, which would otherwise make the same service look different on each side.
$SvcColumns = 'category | service (display name) | start type | account | company | program'
$Agents = 'VMware|Broadcom|Tanium|Tenable|Nessus|Liongard|\\CCM\\|Windows Defender|Microsoft Defender|AzureConnectedMachineAgent|WindowsAzure|' +
          'Microsoft Policy Platform|Microsoft Monitoring Agent|AzureMonitorAgent|Qualys|CrowdStrike|SentinelOne|Splunk|Veeam|' +
          'Commvault|Rapid7|Datadog|Zabbix|SolarWinds|Trend Micro|Symantec|McAfee|Sophos|Carbon Black'
$CompanyOf = @{}
function SvcDetail($s) {
    # Without admin some protected services show no path: Get-Item '' is a binding error, not a quiet miss.
    $exe = "$($s.PathName)" -replace '^"?([^"]*?\.exe).*$', '$1'
    if ($exe -and -not $CompanyOf.ContainsKey($exe)) { $CompanyOf[$exe] = (Get-Item -LiteralPath $exe -ErrorAction SilentlyContinue).VersionInfo.CompanyName }
    $co = if ($exe) { "$($CompanyOf[$exe])" } else { '' }
    $cat = if (-not $exe) { '?' } elseif ("$exe $co" -match $Agents) { 'AGENT' } elseif ($exe -match '^[A-Z]:\\Windows\\') { 'WIN' } else { 'APP?' }
    '{0,-5} | {1,-50} | {2,-14} | {3,-32} | {4,-22} | {5}' -f $cat, "$($s.Name) ($($s.DisplayName))", (StartType $s), $s.StartName, $co, $exe
}
# One group of events as: key | count | first line of the latest message (Get-WinEvent returns newest first).
function EventLine($g) {
    $m = "$($g.Group[0].Message)" -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1
    if (-not $m) { $m = '(no message text)' }
    '{0,-55} | {1,5} | {2}' -f $g.Name, "$($g.Count)x", $m.Trim().Substring(0, [math]::Min(160, $m.Trim().Length))
}

# What each column of a result file is: shown as a heading above that file's lines in the report.
$Columns = @{
    syserr = 'event (source, ID, service) | times since boot | latest message'
    apperr = 'event (source, ID) | times since boot | latest message'
    agent = 'service | status'; drives = 'drive | size | label'; vmtools = 'software | version | publisher'
    dhcp = 'network adapter | DHCP'; autostop = $SvcColumns; services = $SvcColumns; svcacct = 'service | account'
    tasks = 'task | runs as'; ports = 'listening on | process'; portcheck = 'listening on | answers'
    peers = 'peer | answers'; sessions = 'direction | peer | local port'; synsent = 'trying to reach | process'
    sslcert = 'binding | certificate thumbprint | expiry'; tls = 'binding | certificate thumbprint | expiry'
    shares = 'share | folder'
}

# ---------- helpers ----------
$Checks = New-Object System.Collections.Generic.List[object]
$Sum = New-Object System.Collections.Generic.List[string]
$Det = New-Object System.Collections.Generic.List[string]

function Def([hashtable]$d) { $Checks.Add([pscustomobject]$d) }
function Save($name, $lines) {
    $out = @($lines | ForEach-Object { "$_".Trim() } | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $out.Count) { $out = @('(none)') }
    Set-Content -Path (Join-Path $script:Dir "$name.txt") -Value $out -Encoding UTF8
}
function Has($side, $name) { Test-Path (Join-Path $Root "$side\$name.txt") }
function Res($side, $name) {
    $p = Join-Path $Root "$side\$name.txt"
    if (Test-Path $p) { Get-Content $p | Where-Object { $_ -and $_ -ne '(none)' } }
}
function Line($tag, $name, $text) {
    # Result lines are padded into columns; in a one-line summary the padding only wastes the 110 characters.
    $l = '{0,-4} {1,-9} {2}' -f $tag, $name, ("$text" -replace '\s{2,}', ' ')
    $Sum.Add($l.Substring(0, [math]::Min(110, $l.Length)))
}
# Compare one file with AVS. -NewOnly: only what is new on Azure counts. -GoneOnly: only what is
# missing on Azure counts. -InfoOnly: differences are shown as INFO, not DIFF.
# -KeyField n: compare only column n (counted from 0) of lines split at "|"; the rest is shown, not compared.
# -MatchLine: test the expected patterns on the whole line instead of the compared column.
function Check($name, [switch]$NewOnly, [switch]$GoneOnly, [switch]$InfoOnly, [int]$KeyField = -1, [switch]$MatchLine) {
    if ($script:Solo) { Solo $name $KeyField -MatchLine:$MatchLine; return }
    if (-not (Has source $name) -or -not (Has target $name)) { Line MISS $name 'result file missing'; return }
    $s = @(Res source $name); $t = @(Res target $name); $exp = $Expected[$name]
    $key = { param($l) if ($KeyField -ge 0) { "$(($l -split '\|')[$KeyField])".Trim() } else { $l } }
    $test = { param($l) if ($MatchLine) { $l } else { & $key $l } }
    $sk = @($s | ForEach-Object { & $key $_ }); $tk = @($t | ForEach-Object { & $key $_ })
    $onlyS = if ($NewOnly) { @() } else { @($s | Where-Object { $tk -notcontains (& $key $_) }) }
    $onlyT = if ($GoneOnly) { @() } else { @($t | Where-Object { $sk -notcontains (& $key $_) }) }
    $lines = @($onlyS | ForEach-Object { if ($exp -and (& $test $_) -match $exp) { "~ expected : - $_" } else { "- only AVS  : $_" } }) +
             @($onlyT | ForEach-Object { if ($exp -and (& $test $_) -match $exp) { "~ expected : + $_" } else { "+ only Azure: $_" } })
    $real = @($lines | Where-Object { $_ -notlike '~*' })
    $noise = $lines.Count - $real.Count
    $Det.Add("== $name : $($real.Count) differences, $noise expected")
    if ($Columns[$name] -and $lines.Count) { $Det.Add("   columns    : $($Columns[$name])") }
    $lines | ForEach-Object { $Det.Add("   $_") }
    if ($real.Count) { Line $(if ($InfoOnly) { 'INFO' } else { 'DIFF' }) $name ("{0} line(s), e.g. {1}" -f $real.Count, $real[0]) }
    elseif ($noise) { Line PASS $name "($noise expected difference(s), see report)" }
    else { Line PASS $name '' }
}
# Shown side by side, not compared.
function Info($name) {
    if ($script:Solo) { $t = @(Res target $name); Rule INFO $name ($t -join ', ') $t; return }
    $s = @(Res source $name) -join ', '; $t = @(Res target $name) -join ', '
    Line INFO $name "AVS $s -> Azure $t"
    $Det.Add("== $name (info)"); $Det.Add("   AVS  : $s"); $Det.Add("   Azure: $t")
}
# A rule on the test VM alone: tag, summary text, and every line of the result in the report.
function Rule($tag, $name, $text, $lines) {
    Line $tag $name $text
    $Det.Add("== $name ($tag)")
    if ($Columns[$name] -and @($lines).Count) { $Det.Add("   columns: $($Columns[$name])") }
    @($lines) | ForEach-Object { $Det.Add("   $_") }
}
# Without AVS results (no access to the AVS VM, or a recovery point older than "source") a compared
# check is judged on the test VM alone: its lines are listed, still marked "~ expected" when they are.
# Checks in $SoloLook go into the verdict's "look at" when they have unexpected lines: with no baseline,
# only the app owner can say whether they are right.
$SoloLook = 'apperr', 'ports', 'sessions'
function Solo($name, [int]$KeyField = -1, [switch]$MatchLine) {
    $t = @(Res target $name); $exp = $Expected[$name]
    $isExp = { param($l) $k = if ($MatchLine -or $KeyField -lt 0) { $l } else { "$(($l -split '\|')[$KeyField])".Trim() }; $exp -and $k -match $exp }
    $real = @($t | Where-Object { -not (& $isExp $_) })
    $lines = @($t | ForEach-Object { if (& $isExp $_) { "~ expected : $_" } else { $_ } })
    $svc = { param($l) (@($l) | ForEach-Object { ($_ -split '\|')[1].Trim() -replace ' \(.*$', '' }) -join ', ' }
    $tag = 'INFO'; $look = $real.Count -and $SoloLook -contains $name
    $text = switch ($name) {
        autostop {
            $app = @($real | Where-Object { $_ -match '^APP\?' })
            if ($app.Count) { $tag = 'FAIL'; '{0} app service(s) on Auto not running: {1}' -f $app.Count, (& $svc $app) }
            elseif ($real.Count) { '{0} service(s) on Auto not running: {1}' -f $real.Count, (& $svc $real) }
            else { $tag = 'OK'; 'all Auto services running' } }
        services { '{0} agent(s), {1} app service(s)' -f @($t -match '^AGENT').Count, @($t -match '^APP\?').Count }
        tasks {
            # Per-user tasks (OneDrive, Edge, ... named after the user's SID or a GUID) run as whoever logs on.
            $user = @($t | Where-Object { ($_ -split '\|')[0].Trim() -notmatch '(S-1-5-21-[\d-]+|\{[0-9A-Fa-f-]+\})$' -and
                ($_ -split '\|')[1].Trim() -notmatch '^(SYSTEM|LOCAL SERVICE|NETWORK SERVICE|INTERACTIVE|Users|Administrators|S-1-5-[\d-]+|)$' })
            $look = $user.Count -gt 0
            if ($user.Count) { '{0} task(s) on user accounts, fail without DC if domain: {1}' -f $user.Count, (($user | ForEach-Object { ($_ -split '\|')[0].Trim() }) -join ', ') }
            else { '{0} task(s), none on a user account' -f $t.Count } }
        ports { '{0} listening' -f $t.Count }
        http { if ($t.Count) { '{0} URL(s), e.g. {1}' -f $t.Count, $t[0] } else { 'none' } }
        default {
            if (-not $t.Count) { 'none' }
            elseif ($t.Count -le 3) { $t -join ', ' }
            elseif ($real.Count) { '{0} line(s), e.g. {1}' -f $t.Count, ($real[0] -split '\|')[0].Trim() }
            else { '{0} line(s), all expected' -f $t.Count } }
    }
    if ($look) { $script:Look.Add($name) }
    Rule $tag $name $text $lines
}

# ---------- checks, in the order of the Windows sheet ----------

Def @{
    Check   = 'VM boots'; Side = 'both'
    Command = {
        (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
    }
    Process = { param($raw) 'booted {0:yyyy-MM-dd HH:mm} UTC' -f $raw.ToUniversalTime() }
    File    = 'boot'
    Judge   = { Info boot }
}

Def @{
    Check   = 'No boot or System errors'; Side = 'both'
    Command = {
        Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } -ErrorAction SilentlyContinue
    }
    # Key = source + event ID, + service name for service failures; compared without times, so only new kinds
    # of error show. After it: how often, and the first line of the latest message, shown but not compared.
    Process = { param($raw) $raw | Group-Object {
        # The service name is the first non-numeric property (7009 starts with the timeout in ms).
        $what = if ($_.ProviderName -eq 'Service Control Manager') { $_.Properties | ForEach-Object { "$($_.Value)" } | Where-Object { $_ -notmatch '^\d*$' } | Select-Object -First 1 } else { '' }
        ('{0} {1} {2}' -f $_.ProviderName, $_.Id, $what).Trim() } | ForEach-Object { EventLine $_ } }
    File    = 'syserr'
    Judge   = { Check syserr -NewOnly -KeyField 0 }
}

Def @{
    Check   = 'Azure VM agent Ready'; Side = 'target'
    Command = {
        Get-Service WindowsAzureGuestAgent, RdAgent -ErrorAction SilentlyContinue
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-24} | {1}' -f $_.Name, $_.Status } }
    File    = 'agent'
    Judge   = {
        $a = @(Res target agent)
        if ($a -match '^WindowsAzureGuestAgent\s*\|\s*Running$') { Rule OK agent ($a -join ', ') $a } else { Rule FAIL agent ($a -join ', ') $a } }
}

Def @{
    Check   = 'Disk count and sizes match source'; Side = 'both'
    Command = {
        Get-CimInstance Win32_DiskDrive | Select-Object DeviceID, Model, Size
    }
    # The Azure temporary disk is new and expected: left out.
    Process = { param($raw)
        $temp = foreach ($v in @(Get-CimInstance Win32_LogicalDisk -Filter "VolumeName='Temporary Storage'")) {
            foreach ($p in @(Get-CimAssociatedInstance -InputObject $v -ResultClassName Win32_DiskPartition)) {
                (Get-CimAssociatedInstance -InputObject $p -ResultClassName Win32_DiskDrive).DeviceID } }
        $raw | Where-Object { $temp -notcontains $_.DeviceID } | ForEach-Object { [math]::Round($_.Size / 1GB) } |
            Group-Object | ForEach-Object { '{0} x {1} GB disk' -f $_.Count, $_.Name } }
    File    = 'disks'
    Judge   = { Check disks }
}

Def @{
    Check   = 'All disks online'; Side = 'target'
    # Get-Disk needs admin: without it the command fails, no file is written and the summary says so.
    Command = {
        Get-Disk -ErrorAction Stop | Where-Object { $_.IsOffline -or $_.IsReadOnly }
    }
    Process = { param($raw) $raw | ForEach-Object { 'disk {0}{1}{2}' -f $_.Number, $(if ($_.IsOffline) { ' offline' }), $(if ($_.IsReadOnly) { ' read-only' }) } }
    File    = 'offline'
    Judge   = {
        $off = @(Res target offline)
        if (-not (Has target offline)) { Line INFO offline 'not checked: needs admin (use Run Command)' }
        elseif ($off.Count) { Line FAIL offline ($off -join ', ') }
        else { Line OK offline 'no offline or read-only disk' } }
}

Def @{
    Check   = 'Drive letters and volumes match source'; Side = 'both'
    Command = {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object VolumeName -ne 'Temporary Storage'
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-3} | {1,5} GB | {2}' -f $_.DeviceID, [math]::Round($_.Size / 1GB), $_.VolumeName } }
    File    = 'drives'
    Judge   = { Check drives }
}

Def @{
    Check   = 'Hostname correct'; Side = 'both'
    Command = {
        Get-CimInstance Win32_ComputerSystem | Select-Object Name, Domain
    }
    Process = { param($raw) "Host $($raw.Name)", "Domain $($raw.Domain)" }
    File    = 'host'
    Judge   = { Check host }
}

Def @{
    Check   = 'No VMware Tools leftovers'; Side = 'target'
    Command = {
        Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object Publisher -like 'VMware*' | Select-Object DisplayName, DisplayVersion, Publisher
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-45} | {1,-16} | {2}' -f $_.DisplayName, $_.DisplayVersion, $_.Publisher } }
    File    = 'vmtools'
    Judge   = {
        $v = @(Res target vmtools)
        if ($v.Count) { Rule INFO vmtools ('still installed: ' + (($v | ForEach-Object { ($_ -split '\|')[0].Trim() }) -join ', ')) $v } else { Line OK vmtools 'VMware Tools removed' } }
}

Def @{
    Check   = 'Time sync'; Side = 'target'
    Command = {
        w32tm /query /status
    }
    Process = { param($raw) $raw | Select-String '^(Source|Last Successful Sync Time):' | ForEach-Object { $_.Line.Trim() } }
    File    = 'timesrc'
    Judge   = { $ts = @(Res target timesrc); Rule INFO timesrc ($ts -join ', ') $ts }
}

Def @{
    Check   = 'NIC and IP address correct'; Side = 'both'
    Command = {
        Get-NetIPConfiguration
    }
    Process = { param($raw) $raw | ForEach-Object { 'IP {0} | GW {1} | DNS {2}' -f ($_.IPv4Address.IPAddress -join ','),
        ($_.IPv4DefaultGateway.NextHop -join ','), (($_.DNSServer | Where-Object AddressFamily -eq 2).ServerAddresses -join ',') } }
    File    = 'net'
    Judge   = { Info net }
}

Def @{
    Check   = 'Guest uses DHCP'; Side = 'target'
    Command = {
        Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | Where-Object InterfaceAlias -notlike 'Loopback*'
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-30} | DHCP {1}' -f $_.InterfaceAlias, $_.Dhcp } }
    File    = 'dhcp'
    Judge   = {
        $d = @(Res target dhcp); $off = @($d | Where-Object { $_ -like '* DHCP Disabled' })
        if (-not $d.Count) { Line FAIL dhcp 'no connected NIC found' }
        elseif ($off.Count) { Rule FAIL dhcp ('DHCP off, Azure gives the IP by DHCP: ' + ($off -join ', ')) $d }
        else { Line OK dhcp 'DHCP on (normal in Azure)' } }
}

Def @{
    Check   = 'No ghost NIC holding old config'; Side = 'target'
    Command = {
        Get-PnpDevice -Class Net | Where-Object Status -eq 'Unknown'
    }
    # The old VMware NIC always stays hidden after the move. It only hurts if it keeps a static IP,
    # which Windows can then refuse on the new NIC as a duplicate, so the registry is checked for that.
    Process = { param($raw)
        $present = @(Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceGuid })
        $raw | ForEach-Object { "ghost $($_.FriendlyName)" }
        Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces' -ErrorAction SilentlyContinue |
            Where-Object { $present -notcontains $_.PSChildName } | Get-ItemProperty | Where-Object { $_.EnableDHCP -eq 0 } | ForEach-Object {
                $ips = @($_.IPAddress | Where-Object { $_ -and $_ -ne '0.0.0.0' })
                if ($ips) { 'static {0} on missing adapter {1}' -f ($ips -join ','), $_.PSChildName } } }
    File    = 'ghostnic'
    Judge   = {
        $g = @(Res target ghostnic); $st = @($g | Where-Object { $_ -like 'static*' })
        if ($st.Count) { Rule FAIL ghostnic ($st -join ', ') $g }
        elseif ($g.Count) { Rule INFO ghostnic ('{0} hidden NIC(s), no static IP' -f $g.Count) $g }
        else { Line OK ghostnic 'no hidden NIC' } }
}

Def @{
    Check   = 'Automatic services running'; Side = 'both'
    Command = {
        Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State<>'Running'"
    }
    Process = { param($raw) $raw | Where-Object Name -notmatch $PerUser | ForEach-Object { SvcDetail $_ } }
    File    = 'autostop'
    Judge   = { Check autostop -KeyField 1 -MatchLine }
}

Def @{
    Check   = 'System services running as expected'; Side = 'both'
    Command = {
        Get-CimInstance Win32_Service -Filter "State='Running'"
    }
    Process = { param($raw) $raw | Where-Object Name -notmatch $PerUser | ForEach-Object { SvcDetail $_ } }
    File    = 'services'
    Judge   = { Check services -KeyField 1 -MatchLine }
}

Def @{
    Check   = 'Services running as domain accounts'; Side = 'both'
    Command = {
        Get-CimInstance Win32_Service | Where-Object StartName -notmatch '^(LocalSystem|NT AUTHORITY\\|NT SERVICE\\)' | Select-Object Name, StartName, State
    }
    # Local accounts (.\user, HOST\user) keep working without a DC: left out.
    Process = { param($raw) $raw | Where-Object { $_.StartName -and $_.StartName -notmatch '^\.\\' -and $_.StartName -notlike "$env:COMPUTERNAME\*" } |
        ForEach-Object { '{0,-40} | {1}' -f $_.Name, $_.StartName } }
    File    = 'svcacct'
    Judge   = {
        $sa = @(Res target svcacct)
        if ($sa.Count) { Rule INFO svcacct ('{0} on domain accounts, fail without DC: {1}' -f $sa.Count, (($sa | ForEach-Object { ($_ -split '\|')[0].Trim() }) -join ', ')) $sa }
        else { Line OK svcacct 'none on domain accounts' } }
}

Def @{
    Check   = 'Application log errors since boot'; Side = 'both'
    Command = {
        Get-WinEvent -FilterHashtable @{ LogName = 'Application'; Level = 1, 2; StartTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime } -ErrorAction SilentlyContinue
    }
    # Same line layout as the System log check.
    Process = { param($raw) $raw | Group-Object { '{0} {1}' -f $_.ProviderName, $_.Id } | ForEach-Object { EventLine $_ } }
    File    = 'apperr'
    Judge   = { Check apperr -NewOnly -KeyField 0 }
}

Def @{
    Check   = 'Scheduled tasks present'; Side = 'both'
    Command = {
        Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' }
    }
    # State left out: it changes between runs.
    Process = { param($raw) $raw | ForEach-Object { '{0,-70} | {1}' -f ($_.TaskPath + $_.TaskName), $_.Principal.UserId } }
    File    = 'tasks'
    Judge   = { Check tasks -GoneOnly:$Partial }
}

Def @{
    Check   = 'Listening ports match source'; Side = 'both'
    Command = {
        Get-NetTCPConnection -State Listen | Sort-Object LocalPort
    }
    # Dynamic ports 49152+ change at every boot: left out. The VM's own IP becomes MY-IP.
    Process = { param($raw)
        $myIPs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.IPAddress })
        $raw | Where-Object LocalPort -lt 49152 | ForEach-Object {
            $addr = $_.LocalAddress
            if ($myIPs -contains $addr) { $addr = 'MY-IP' } elseif ($addr -like 'fe80*') { $addr = 'LINK-LOCAL' }
            '{0,-30} | {1}' -f "${addr}:$($_.LocalPort)", (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
    File    = 'ports'
    Judge   = { Check ports }
}

Def @{
    Check   = 'Local TCP ports respond'; Side = 'target'
    Command = {
        Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notmatch ':' -and $_.LocalPort -lt 49152 } | Select-Object LocalAddress, LocalPort -Unique | ForEach-Object {
            $h = if ($_.LocalAddress -eq '0.0.0.0') { '127.0.0.1' } else { $_.LocalAddress }
            $c = New-Object Net.Sockets.TcpClient
            $open = try { $c.ConnectAsync($h, $_.LocalPort).Wait(2000) } catch { $false }
            $c.Close()
            [pscustomobject]@{ Endpoint = "${h}:$($_.LocalPort)"; Open = $open } }
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-30} | {1}' -f $_.Endpoint, $(if ($_.Open) { 'OK' } else { 'FAIL' }) } }
    File    = 'portcheck'
    Judge   = {
        $pc = @(Res target portcheck); $bad = @($pc | Where-Object { $_ -like '* FAIL' })
        if ($bad.Count) { Rule FAIL portcheck ($bad -join ', ') $pc } else { Rule OK portcheck ('{0} listening port(s) answer' -f $pc.Count) $pc } }
}

Def @{
    Check   = 'Inter-tier connectivity'; Side = 'target'
    # $Peers comes from -Peers. In the sheet it reads '<peer-ip>:<port>', '<peer-ip>:<port>' instead.
    Command = {
        $Peers | ForEach-Object {
            $h, $p = $_ -split ':'
            [pscustomobject]@{ Endpoint = $_; Open = Test-NetConnection $h -Port $p -InformationLevel Quiet -WarningAction SilentlyContinue } }
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-30} | {1}' -f $_.Endpoint, $(if ($_.Open) { 'OK' } else { 'FAIL' }) } }
    File    = 'peers'
    Judge   = {
        $pr = @(Res target peers); $bad = @($pr | Where-Object { $_ -like '* FAIL' })
        if (-not $pr.Count) { Line INFO peers 'not run: target -Peers host:port,...' }
        elseif ($bad.Count) { Rule FAIL peers ($bad -join ', ') $pr } else { Rule OK peers ($pr -join ', ') $pr } }
}

Def @{
    Check   = 'Established connections between tiers'; Side = 'both'
    Command = {
        Get-NetTCPConnection -State Established | Where-Object RemoteAddress -notmatch '^(127\.|::1$)' | Sort-Object RemoteAddress
    }
    # Outbound as peer:port, inbound as peer -> local port; ephemeral ports left out.
    Process = { param($raw)
        $myIPs = @(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' | ForEach-Object { $_.IPAddress })
        $listen = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | ForEach-Object { $_.LocalPort })
        $raw | Where-Object { $myIPs -notcontains $_.RemoteAddress } | ForEach-Object {
            if ($listen -contains $_.LocalPort) { 'in  | {0,-30} | :{1}' -f $_.RemoteAddress, $_.LocalPort }
            elseif ($_.RemotePort -lt 49152) { 'out | {0}:{1}' -f $_.RemoteAddress, $_.RemotePort }
            else { 'out | {0}' -f $_.RemoteAddress } } }
    File    = 'sessions'
    # Peers outside the test set always vanish in the isolated VNet, so a difference is shown, not failed.
    Judge   = { Check sessions -InfoOnly }
}

Def @{
    Check   = 'Blocked outbound attempts'; Side = 'target'
    Command = {
        Get-NetTCPConnection -State SynSent -ErrorAction SilentlyContinue
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-30} | {1}' -f "$($_.RemoteAddress):$($_.RemotePort)", (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName } }
    File    = 'synsent'
    Judge   = {
        $ss = @(Res target synsent)
        if ($ss.Count) { Rule INFO synsent ('{0} blocked: {1}' -f $ss.Count, ($ss -join ', ')) $ss } else { Line OK synsent 'no blocked outbound' } }
}

Def @{
    Check   = 'TLS certificates and bindings'; Side = 'both'
    Command = {
        netsh http show sslcert
    }
    # One line per binding, with the expiry of its certificate from the My or WebHosting store.
    Process = { param($raw)
        $certs = @(Get-ChildItem Cert:\LocalMachine\My, Cert:\LocalMachine\WebHosting -ErrorAction SilentlyContinue)
        $bind = ''
        $raw | ForEach-Object {
            if ($_ -match '^\s*(IP:port|Hostname:port|Central Certificate Store)\s*:\s*(\S+)') { $bind = $Matches[2] }
            elseif ($_ -match '^\s*Certificate Hash\s*:\s*(\S+)') {
                $hash = $Matches[1].ToUpper(); $c = $certs | Where-Object Thumbprint -eq $hash | Select-Object -First 1
                if ($c) { '{0,-30} | {1,-40} | expires {2:yyyy-MM-dd}' -f $bind, $hash, $c.NotAfter } else { '{0,-30} | {1,-40} | cert missing' -f $bind, $hash } } } }
    File    = 'sslcert'
    Judge   = {
        Check sslcert -GoneOnly:$Partial
        $today = Get-Date -Format 'yyyy-MM-dd'
        $bad = @(Res target sslcert | Where-Object { $_ -like '* cert missing' -or ($_ -match 'expires (\S+)$' -and $Matches[1] -lt $today) })
        if ($bad.Count) { Rule FAIL tls ($bad -join ', ') $bad } else { Line OK tls 'bound certs present and valid' } }
}

Def @{
    Check   = 'File shares present'; Side = 'both'
    Command = {
        Get-CimInstance Win32_Share -Filter 'Type=0' | Where-Object Name -notmatch '\$$'
    }
    Process = { param($raw) $raw | ForEach-Object { '{0,-20} | {1}' -f $_.Name, $_.Path } }
    File    = 'shares'
    Judge   = { Check shares -GoneOnly:$Partial }
}

Def @{
    Check   = 'Domain dependency (expected failure)'; Side = 'target'
    Command = {
        nltest "/sc_query:$((Get-CimInstance Win32_ComputerSystem).Domain)" 2>&1
    }
    Process = { param($raw) $raw | Select-String 'Status =' | ForEach-Object { $_.Line.Trim() } }
    File    = 'domain'
    Judge   = { $dm = @(Res target domain); Rule INFO domain ('secure channel: ' + ($dm -join ', ')) $dm }
}

Def @{
    Check   = 'Extra: OS version'; Side = 'both'
    Command = {
        Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version
    }
    Process = { param($raw) "OS $($raw.Caption)", "Version $($raw.Version)" }
    File    = 'os'
    Judge   = { Check os }
}

Def @{
    Check   = 'Extra: time zone'; Side = 'both'
    Command = {
        Get-TimeZone
    }
    Process = { param($raw) $raw.Id }
    File    = 'timezone'
    Judge   = { Check timezone }
}

Def @{
    Check   = 'Extra: used space per drive'; Side = 'both'
    Command = {
        Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' | Where-Object VolumeName -ne 'Temporary Storage'
    }
    Process = { param($raw) $raw | ForEach-Object { '{0} {1} GB' -f $_.DeviceID, [math]::Round(($_.Size - $_.FreeSpace) / 1GB) } }
    File    = 'used'
    Judge   = { Info used }
}

Def @{
    Check   = 'Extra: HTTP.sys URLs'; Side = 'both'
    Command = {
        netsh http show servicestate
    }
    Process = { param($raw) $raw | Select-String 'HTTPS?://' | ForEach-Object { $_.Line.Trim().ToUpper() } }
    File    = 'http'
    Judge   = { Check http }
}

Def @{
    Check   = 'Extra: VM size'; Side = 'both'
    Command = {
        Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfLogicalProcessors, TotalPhysicalMemory, Manufacturer
    }
    # CPU and RAM can change with the VM size: shown, not compared.
    Process = { param($raw) '{0} CPU, {1} GB RAM, {2}' -f $raw.NumberOfLogicalProcessors, [math]::Round($raw.TotalPhysicalMemory / 1GB), $raw.Manufacturer }
    File    = 'size'
    Judge   = { Info size }
}

# ---------- run ----------
function Collect($side) {
    $onAzure = (Get-CimInstance Win32_ComputerSystem).Manufacturer -eq 'Microsoft Corporation'
    if ($side -eq 'source' -and $onAzure) { 'Stop: this is the Azure VM. Run "source" on the AVS VM.'; exit 1 }
    if ($side -eq 'target' -and -not $onAzure) { 'Stop: this is not the Azure VM. Run "target" on the test VM.'; exit 1 }
    $script:Dir = Join-Path $Root $side
    New-Item -ItemType Directory -Force -Path $script:Dir | Out-Null
    # Results of an earlier run would otherwise survive a check that fails or is skipped this time.
    Remove-Item (Join-Path $script:Dir '*.txt') -ErrorAction SilentlyContinue
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    Save elevated "$admin"

    foreach ($chk in $Checks) {
        if ($chk.Side -eq 'target' -and $side -ne 'target') { continue }
        try {
            $raw = @(& $chk.Command)
            # Piping $null into ForEach-Object runs it once, which would write a blank line as a result.
            if ($raw.Count) { Save $chk.File (& $chk.Process $raw) } else { Save $chk.File @() }
        } catch { "Error in '$($chk.Check)': $_" }
    }

    Set-Content -Path (Join-Path $script:Dir 'collected.txt') -Encoding UTF8 -Value (
        '{0} {1} collected {2:yyyy-MM-dd HH:mm} UTC' -f $side, $env:COMPUTERNAME, (Get-Date).ToUniversalTime())
    "Collected $side results in $script:Dir"
    if (-not $admin) { 'Not elevated: tasks, shares and TLS may be incomplete. Re-run from an elevated prompt.' }
}

function Compare-All {
    if (-not (Test-Path (Join-Path $Root 'target'))) { "No $Root\target yet: run target first."; exit 1 }
    # collected.txt is written last, so an interrupted or empty source\ also counts as no AVS results.
    $script:Solo = -not (Has source collected)
    $script:NotCol = New-Object System.Collections.Generic.List[string]
    $script:Look = New-Object System.Collections.Generic.List[string]
    $script:Partial = (Res source elevated) -eq 'False'
    if ($Solo -and (Res target elevated) -eq 'False') { Line INFO noadmin 'test VM run not elevated: tasks, shares and TLS bindings may be incomplete' }
    foreach ($chk in $Checks) {
        if ($Solo -and -not (Has target $chk.File)) { $NotCol.Add($chk.File); continue }
        try { & $chk.Judge } catch { Line ERR $chk.File "$_" }
    }

    if ($Solo) {
        if (@($Sum) -match '^INFO svcacct ') { $Look.Add('svcacct') }
        $vm = "$(Res target collected)" -replace '^target (\S+).*$', '$1'
        $head = @("source $vm not collected (no access to AVS)") + @(Res target collected)
        $note = @('No PASS/DIFF lines: there is no AVS data to compare with.')
        $legend = 'OK/FAIL = rule on the test VM, INFO = shown only, ~ expected = normal after the move'
        $badTag = '^(FAIL|ERR)\s'
    } else {
        $head = @(Res source collected) + @(Res target collected); $note = @()
        $legend = 'PASS/DIFF = compared with AVS, OK/FAIL = rule on the test VM, INFO = shown only, ~ expected = normal after the move'
        $badTag = '^(DIFF|FAIL|MISS|ERR)\s'
    }
    $counts = @($Sum) | ForEach-Object { ($_ -split ' ')[0] } | Group-Object | Sort-Object Name | ForEach-Object { '{0} {1}' -f $_.Count, $_.Name }
    $bad = @(@($Sum) | Where-Object { $_ -match $badTag -or ($_ -match '^INFO\s+(\S+)' -and $Look -contains $Matches[1]) } | ForEach-Object { ($_ -split '\s+')[1] })
    # Without a baseline nothing can be called "all good".
    $none = if ($Solo) { 'no FAIL, review INFO lines with the app owner' } else { 'all good, review INFO lines' }
    $verdict = 'RESULT: {0} -> {1}' -f ($counts -join ', '),
        $(if ($bad.Count) { 'look at: ' + ($bad -join ', ') + '  (migcheck.ps1 show <name>)' } else { $none })
    # Added after the counts: it is not a result tag.
    if ($NotCol.Count) { $Sum.Add('NOT COLLECTED  ' + ($NotCol -join ', ')) }
    Set-Content -Path (Join-Path $Root 'report.txt') -Encoding UTF8 -Value (@($head) + $legend + $note + '' + $Sum + $verdict + '' + $Det)
    # Run Command keeps only the last 4 KB of output, so the verdict goes last.
    $head; $note; $Sum; "Detail: $Root\report.txt"; $verdict
}

# Report sections start with "== <name>", so one check can be printed without the rest.
function Show-Report {
    $rp = Join-Path $Root 'report.txt'
    if (-not (Test-Path $rp)) { "No $rp yet: run target or compare first."; exit 1 }
    $r = Get-Content $rp
    if (-not $Name) {
        # Details first and summary last: Run Command keeps the end of the output if it is too long.
        $sum = @($r | Where-Object { $_ -match '^(INFO|DIFF|FAIL|MISS|ERR)\s|^NOT COLLECTED' })
        $parts = ($r -join "`n") -split '(?m)^(?===)'
        foreach ($n in ($sum | ForEach-Object { ($_ -split '\s+')[1] })) { $parts | Where-Object { $_ -match "^== $([regex]::Escape($n))\b" } }
        ''; $sum; $r | Where-Object { $_ -like 'RESULT:*' }
        return }
    $part = (($r -join "`n") -split '(?m)^(?===)') | Where-Object { $_ -match "^== $([regex]::Escape($Name))\b" }
    if ($part) { $part } else { "No check '$Name' in the report. Names: " + ((($r -match '^== ') | ForEach-Object { ($_ -split '\s+')[1] }) -join ', ') }
}

switch ($Mode) {
    'source'  { Collect 'source' }
    'target'  { Collect 'target'; Compare-All }
    'compare' { Compare-All }
    'show'    { Show-Report }
}
