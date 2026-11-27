#!/usr/bin/env bash
# migcheck.sh - test-migration checks for a Linux VM (AVS -> Azure). Linux twin of migcheck.ps1. Read-only.
#
# Each check is one "def" below, named exactly as column A of the Linux sheet in
# "Test Migration Infrastructure Checks", in the same order. A check has:
#   cmd_<file>     what is run; column C of the sheet is this, verbatim, to run by hand
#   proc_<file>    turns the command's output into sorted text lines, so a diff shows only real changes
#   <file>         the lines are written to <folder>/<side>/<file>.txt
#   judge_<file>   how the summary rates that file
# Checks named "Extra: ..." have no sheet row.
#
# Results go in the folder you run the script from (the current directory), so run every step from
# the same folder, e.g. ~/migcheck. Do "source" on the AVS VM BEFORE the recovery point you test from:
# the test VM then boots with the script and the AVS results already in that folder.
#
#   <folder>/migcheck.sh
#   <folder>/source/      results from the AVS VM
#   <folder>/target/      results from the test VM
#   <folder>/report.txt   full comparison
#
# --root DIR uses DIR instead of the current directory.
#
# No sudo needed, on either VM. Without root a few checks see less and the script adapts:
#   ports   owners hidden: only address and port are compared
#   jobs    other users' crontabs hidden: only jobs missing on Azure count
#   synsent program names hidden
#   kernelerr, errors  journal readable only for members of systemd-journal / adm / wheel:
#                      otherwise the Azure errors are listed, not compared
# The summary then has one "noroot" INFO line. With sudo, or as root (Run Command), nothing is reduced.
#
# 1. AVS VM (SSH, your account):
#      cd ~/migcheck && bash migcheck.sh source
#    Then wait for a recovery point newer than the time in ~/migcheck/source/collected.txt.
# 2. Test VM, from the same folder. Run Command starts in an agent folder, not yours, so cd first:
#      cd /home/<user>/migcheck && bash migcheck.sh target
#    Collects target/, compares, prints one line per check. The last line is the verdict.
#    Inter-tier test: add  --peers 10.1.2.3:1433,app2.fqdn:443
#    Without <folder>/source (no access to AVS) the report is on the test VM alone: no PASS/DIFF,
#    compared checks are listed as INFO, and failed app units FAIL.
# 3. Compare again only:   cd /home/<user>/migcheck && bash migcheck.sh compare
#    Problems and INFO:    cd /home/<user>/migcheck && bash migcheck.sh show   (their detail, then summary and verdict)
#    Detail of one check:  cd /home/<user>/migcheck && bash migcheck.sh show services   (the name after the tag)
#    Run Command keeps only the last 4 KB of output, so read the report one check at a time with "show".
#
# Summary: PASS / DIFF = compared with AVS, OK / FAIL = rule on the test VM alone, INFO = shown only.
# Differences expected after the move (VMware -> Azure, isolated test network) are listed as
# "~ expected" in the report and do not count as DIFF.
# If bash says  $'\r': command not found  the file got Windows line endings. Fix:  sed -i 's/\r$//' migcheck.sh

MODE=$1; shift
ROOT=$PWD; PEERS=""; NAME=""
while [ $# -gt 0 ]; do
  case "$1" in
    --peers) PEERS=${2//,/ }; shift 2 ;;
    --root)  ROOT=$2; shift 2 ;;
    *)       NAME=$1; shift ;;
  esac
done
PATH="$PATH:/sbin:/usr/sbin"
export LC_ALL=C
case "$MODE" in source|target|compare|show) ;;
  *) echo 'Usage: migcheck.sh source | target [--peers host:port,...] | compare | show [check]'; exit 1 ;; esac

# Expected after the move: VMware tools go, the Azure agent and Hyper-V daemons come, the Arc agent stops
# on an Azure VM (it listens on 4034x), and the isolated test VNet has no IdM, DNS, NTP or NFS.
MOVE='vmware|vmtoolsd|open-vm-tools|vgauth|waagent|walinuxagent|hyperv|hv_|hv-|serial-getty|himds|arcproxy|gcad|extd|azcmagent|azure'
NOIDM='sssd|realmd|krb5|kerberos|ldap|nfs|rpc|chrony|ntp|resolv|dns'
# No route to Red Hat, Ubuntu or Satellite servers either, so subscription and update jobs fail
# (the Linux side of Windows activation failing without KMS).
NOUPDATE='rhsm|subscription-manager|insights-client|dnf-makecache|yum-makecache|packagekit|apt-daily|unattended-upgrade|snapd|landscape'
# The test VM boots from a copy of a running disk, so journald finds its files not closed properly.
UNCLEAN='uncleanly shut down|unclean shutdown'
# Units not enabled at boot (static, disabled, indirect, transient) run when something starts them, so
# whether they run depends on the minutes before the snapshot: listed, not counted. Enabled ones count.
ONDEMAND='\| *(static|disabled|indirect|transient) *\|'
expected() {
  case "$1" in
    ports) echo ":4034[0-9]( |$)|$MOVE" ;;
    services) echo "$MOVE|$ONDEMAND" ;;
    software|jobs) echo "$MOVE" ;;
    failed) echo "$MOVE|$NOIDM|$NOUPDATE" ;;
    errors|kernelerr) echo "$MOVE|$NOIDM|$NOUPDATE|$UNCLEAN|mount" ;;
  esac
}

# ---------- helpers ----------
CHECKS=()
def() { CHECKS+=("$1|$2|$3"); }   # file | side (both or target) | name in the sheet
# One sorted file per check, no PIDs or times inside, so a diff shows only real changes.
save() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | grep -v '^$' | sort -u > "$DIR/$1.txt"
  [ -s "$DIR/$1.txt" ] || echo '(none)' > "$DIR/$1.txt"
}
# Journal lines grouped by kind: program: message with numbers as N (the compared key) | how often |
# the latest message as logged. Date, host and PID are dropped.
journal_events() {
  sed -E 's/^[A-Za-z]{3} [ 0-9]{2} [0-9:]{8} [^ ]+ //; s/\[[0-9]+\]//' |
    awk '{k = $0; gsub(/[0-9]+/, "N", k); k = substr(k, 1, 70); n[k]++; last[k] = substr($0, 1, 140)}
         END {for (k in n) printf "%-70s | %5s | %s\n", k, n[k] "x", last[k]}'
}
# One unit per line, in aligned columns, the category first so the file sorts into groups:
#   AGENT  monitoring, security or management tools (known names below)
#   APP?   program under /opt, /usr/local, /home, /srv, /data or /app, a unit the admin added in
#          /etc/systemd/system, or an init.d script: most likely the application; the app owner confirms
#   OS     the rest (distribution packages)
#   MOUNT, TIMER, ... for units that are not services
# Only the unit name is compared (key=2); the rest is shown.
AGENTS='tanium|nessus|tenable|qualys|falcon|crowdstrike|splunk|datadog|zabbix|waagent|walinuxagent|azure|himds|arcproxy|gcad|extd|azcmagent|omsagent|mdatp|wdavdaemon|sentinel|commvault|veeam|liongard|rapid7|ir_agent|ds_agent|trend|mcafee|sophos|carbonblack|cbagent|vmtoolsd|vmware|vgauth|open-vm-tools|amazon-ssm'
unit_detail() {
  local units; units=$(cat); [ -n "$units" ] || return
  # shellcheck disable=SC2086  # one argument per unit
  systemctl show -p Id -p Description -p User -p UnitFileState -p FragmentPath -p SourcePath -p ExecStart $units 2>/dev/null |
    awk -v agents="$AGENTS" '
      function out(  t, c) {
        if (id == "") return
        t = id; sub(/.*\./, "", t)
        if (tolower(id " " prog) ~ agents) c = "AGENT"
        else if (t != "service") c = toupper(t)
        else if (prog ~ /^\/(opt|usr\/local|home|srv|data|app)\// || frag ~ /^\/etc\/systemd\/system\/[^\/]+$/ || src ~ /init\.d/) c = "APP?"
        else c = "OS"
        printf "%-6s | %-50s | %-10s | %-14s | %s\n", c, id " (" desc ")", state, (user == "" ? "root" : user), prog
        id = desc = user = state = frag = src = prog = ""
      }
      /^$/ {out(); next}
      {k = $0; sub(/=.*/, "", k); v = $0; sub(/^[^=]*=/, "", v)}
      k == "Id" {id = v} k == "Description" {desc = v} k == "User" {user = v} k == "UnitFileState" {state = v}
      k == "FragmentPath" {frag = v} k == "SourcePath" {src = v}
      k == "ExecStart" && prog == "" && match(v, /path=[^ ;]+/) {prog = substr(v, RSTART + 5, RLENGTH - 5)}
      END {out()}'
}
UNITCOLS='category | unit (description) | enabled at boot | user | program'
# What each column of a result file is: shown as a heading above that file's lines in the report.
columns() {
  case "$1" in
    kernelerr|errors) echo 'kind of error (program: message, numbers as N) | times since boot | latest message' ;;
    services|failed) echo "$UNITCOLS" ;;
    agent) echo 'unit | state' ;; drives) echo 'mounted on | type | size' ;; vmtools) echo 'unit | loaded | state' ;;
    dhcp) echo 'interface | address | DHCP' ;; jobs) echo 'kind | job' ;; ports) echo 'listening on | process' ;;
    portcheck) echo 'listening on | answers' ;; peers) echo 'peer | answers' ;; sessions) echo 'direction | peer | local port' ;;
    synsent) echo 'trying to reach | process' ;; tls|tlsexpiry) echo 'listening on | certificate subject | expiry' ;;
    netfs) echo 'mounted on | source' ;; software) echo 'package | version' ;;
  esac
}

# ---------- checks, in the order of the Linux sheet ----------

def boot both 'VM boots'
cmd_boot() {
  uptime -s
}
proc_boot() { sed 's/^/booted /'; }
judge_boot() { info boot; }

def kernelerr both 'No kernel or boot errors'
cmd_kernelerr() {
  journalctl -b -k -p err --no-pager -q
}
proc_kernelerr() { journal_events; }
judge_kernelerr() { journal_check kernelerr; }

def agent target 'Azure VM agent Ready'
cmd_agent() {
  systemctl list-units --all --no-legend --no-pager --plain 'waagent*' 'walinuxagent*'
}
proc_agent() { awk '{printf "%-28s | %s\n", $1, $3}'; }
judge_agent() {
  local a; a=$(res target agent | join ', ')
  if res target agent | grep -qE '^(waagent|walinuxagent)\.service +\| active$'; then rule OK agent "$a" agent; else line FAIL agent "${a:-agent not installed}"; fi
}

def disks both 'Disk count and sizes match source'
cmd_disks() {
  lsblk -db -o NAME,SIZE,TYPE,MODEL
}
# The Azure temporary disk is new and expected: left out.
proc_disks() {
  awk -v t="$TEMPDISK" 'NR > 1 && $3 == "disk" && $1 != t {printf "%d\n", $2 / 1073741824 + 0.5}' |
    sort -n | uniq -c | awk '{print $1 " x " $2 " GB disk"}'
}
judge_disks() { check disks; }

def drives both 'Filesystems mounted per fstab'
cmd_drives() {
  df -PTk -l -x tmpfs -x devtmpfs -x squashfs -x overlay
}
proc_drives() { awk -v t="$TEMPDEV" 'NR > 1 && (t == "" || index($1, t) != 1) {printf "%-25s | %-6s | %5d GB\n", $7, $2, $3 / 1048576 + 0.5}'; }
judge_drives() { check drives; }

def hvdrivers target 'Hyper-V drivers loaded'
cmd_hvdrivers() {
  ls /sys/bus/vmbus/drivers
}
proc_hvdrivers() { cat; }
judge_hvdrivers() {
  local d miss=""
  for d in hv_storvsc hv_netvsc hv_utils; do res target hvdrivers | grep -qx "$d" || miss="$miss $d"; done
  if [ -z "$miss" ]; then line OK hvdrivers 'hv_storvsc, hv_netvsc, hv_utils loaded'
  else rule FAIL hvdrivers "missing:$miss" hvdrivers; fi
}

def vmtools target 'No VMware tools leftovers failing'
cmd_vmtools() {
  systemctl list-units --all --no-legend --no-pager --plain | grep -iE 'vmtoolsd|vmware|vgauth'
}
proc_vmtools() { awk '{printf "%-35s | %-8s | %s %s\n", $1, $2, $3, $4}'; }
judge_vmtools() {
  local v; v=$(res target vmtools | join ', ')
  if res target vmtools | grep -q ' failed'; then rule FAIL vmtools "failing: $v" vmtools
  elif [ -n "$v" ]; then rule INFO vmtools "still there, not failing: $v" vmtools
  else line OK vmtools 'VMware tools removed'; fi
}

def host both 'Hostname correct'
cmd_host() {
  hostname -s
}
proc_host() { sed 's/^/Host /'; }
judge_host() { check host; }

def timesrc target 'Time sync'
cmd_timesrc() {
  timedatectl
}
proc_timesrc() { grep -E 'synchronized|NTP' | sed 's/^ *//'; }
judge_timesrc() { rule INFO timesrc "$(res target timesrc | join ', ')" timesrc; }

def net both 'NIC and IP address correct'
cmd_net() {
  ip -4 -o addr show scope global
}
# IP and DNS change by design: shown, not compared.
proc_net() {
  local gw dns
  gw=$(ip -4 route show default 2>/dev/null | awk '{print $3; exit}')
  dns=$(awk '/^nameserver/ {print $2}' /etc/resolv.conf 2>/dev/null | paste -sd, -)
  awk -v gw="$gw" -v dns="$dns" '{split($4, a, "/"); print "IP " a[1] " (" $2 ") | GW " gw " | DNS " dns}'
}
judge_net() { info net; }

def dhcp target 'Guest uses DHCP'
cmd_dhcp() {
  ip -4 -o addr show scope global
}
# "dynamic" in ip addr = the address came from DHCP.
proc_dhcp() { awk '{split($4, a, "/"); printf "%-12s | %-16s | DHCP %s\n", $2, a[1], (($0 ~ / dynamic /) ? "True" : "False")}'; }
judge_dhcp() {
  if ! res target dhcp | grep -q .; then line FAIL dhcp 'no IPv4 address found'
  elif res target dhcp | grep -q 'DHCP False$'; then rule FAIL dhcp "static IP, Azure gives the IP by DHCP: $(res target dhcp | grep 'DHCP False$' | join ', ')" dhcp
  else line OK dhcp 'DHCP on (normal in Azure)'; fi
}

def failed both 'No failed systemd units'
cmd_failed() {
  systemctl --failed --no-legend --no-pager --plain
}
proc_failed() { awk '{print $1}' | unit_detail; }
judge_failed() { check failed newonly key=2 matchline; }

def services both 'System services running as expected'
cmd_services() {
  systemctl list-units --type=service --state=running --no-legend --no-pager --plain
}
# user@ sessions depend on who is logged on: left out.
proc_services() { awk '{print $1}' | grep -v '^user@[0-9]*\.service$' | unit_detail; }
judge_services() { check services key=2 matchline; }

def errors both 'Journal errors since boot'
cmd_errors() {
  journalctl -b -p err --no-pager -q
}
proc_errors() { journal_events; }
judge_errors() { journal_check errors; }

def jobs both 'Scheduled jobs present'
cmd_jobs() {
  find /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron -type f 2>/dev/null
  systemctl list-timers --all --no-legend --no-pager
}
proc_jobs() { awk '/^\// {print "cron  | " $0; next} {for (i = 1; i <= NF; i++) if ($i ~ /\.timer$/) {print "timer | " $i; break}}'; }
judge_jobs() { if [ "$PARTIAL" = 1 ]; then check jobs goneonly; else check jobs; fi; }

def ports both 'Listening ports match source'
cmd_ports() {
  ss -ltnp
}
# Ephemeral ports change at every start: left out. The VM's own IP becomes MY-IP. "-" = owner not visible.
proc_ports() {
  awk -v low="$LOW" -v myips="$MYIPS" 'NR > 1 {
    port = $4; sub(/.*:/, "", port); addr = $4; sub(/:[^:]*$/, "", addr)
    if (port + 0 >= low) next
    ip = addr; gsub(/\[|\]/, "", ip); sub(/%.*/, "", ip)
    if (index(myips, " " ip " ")) addr = "MY-IP"; else if (ip ~ /^fe80/) addr = "LINK-LOCAL"
    proc = "-"; if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
    printf "%-30s | %s\n", addr ":" port, proc }'
}
# Without root on either side the owners are mostly "-", so then only address and port are compared.
judge_ports() { if [ "$PARTIAL" = 1 ]; then check ports key=1; else check ports; fi; }

def portcheck target 'Local TCP ports respond'
cmd_portcheck() {
  ss -ltn | awk 'NR > 1 {print $4}' | sort -u | while read -r a; do
    h=${a%:*}; h=${h#[}; h=${h%]}; h=${h%%\%*}
    case $h in '*'|0.0.0.0|::) h=127.0.0.1 ;; esac
    timeout 3 bash -c "</dev/tcp/$h/${a##*:}" 2>/dev/null && echo "$a OK" || echo "$a FAIL"
  done
}
proc_portcheck() { awk -v low="$LOW" '{p = $1; sub(/.*:/, "", p); if (p + 0 < low) printf "%-30s | %s\n", $1, $2}'; }
judge_portcheck() {
  local n; n=$(res target portcheck | grep -c .)
  if res target portcheck | grep -q ' FAIL$'; then rule FAIL portcheck "$(res target portcheck | grep ' FAIL$' | join ', ')" portcheck
  else rule OK portcheck "$n listening port(s) answer" portcheck; fi
}

def tls both 'TLS certificate served'
cmd_tls() {
  ss -ltn | awk 'NR > 1 {print $4}' | sort -u | while read -r a; do
    h=${a%:*}; h=${h#[}; h=${h%]}; h=${h%%\%*}
    case $h in '*'|0.0.0.0|::) h=127.0.0.1 ;; *:*) h="[$h]" ;; esac
    c=$(echo | timeout 5 openssl s_client -connect "$h:${a##*:}" 2>/dev/null | openssl x509 -noout -subject -enddate 2>/dev/null)
    [ -n "$c" ] && echo "$a" $c
  done
}
# One line per TLS port: subject and expiry date. The VM's own IP becomes MY-IP.
proc_tls() {
  local a rest end e ip today; today=$(date -u +%Y-%m-%d)
  while read -r a rest; do
    ip=${a%:*}; ip=${ip#[}; ip=${ip%]}
    case "$MYIPS" in *" $ip "*) a="MY-IP:${a##*:}" ;; esac
    end=${rest##*notAfter=}; e=$(date -u -d "$end" +%Y-%m-%d 2>/dev/null)
    printf '%-28s | %s | expires %s\n' "$a" "${rest%% notAfter=*}" "${e:-$end}$([ -n "$e" ] && [ "$e" \< "$today" ] && echo ' EXPIRED')"
  done
}
judge_tls() {
  check tls
  if res target tls | grep -q ' EXPIRED$'; then line FAIL tlsexpiry "$(res target tls | grep ' EXPIRED$' | join ', ')"
  else line OK tlsexpiry 'no expired certificate'; fi
}

def peers target 'Inter-tier connectivity'
# $PEERS comes from --peers. In the sheet it reads <peer-ip>:<port> <peer-ip>:<port> instead.
cmd_peers() {
  for t in $PEERS; do timeout 3 bash -c "</dev/tcp/${t%:*}/${t##*:}" 2>/dev/null && echo "$t OK" || echo "$t FAIL"; done
}
proc_peers() { awk '{printf "%-30s | %s\n", $1, $2}'; }
judge_peers() {
  if ! res target peers | grep -q .; then line INFO peers 'not run: target --peers host:port,...'
  elif res target peers | grep -q ' FAIL$'; then rule FAIL peers "$(res target peers | grep ' FAIL$' | join ', ')" peers
  else rule OK peers "$(res target peers | join ', ')" peers; fi
}

def sessions both 'Established connections between tiers'
cmd_sessions() {
  ss -tn state established
}
# Outbound as peer:port, inbound as peer -> local port; ephemeral ports left out.
proc_sessions() {
  local listen; listen=" $(ss -ltn 2>/dev/null | awk 'NR > 1 {n = split($4, a, ":"); printf "%s ", a[n]}')"
  awk -v low="$LOW" -v myips="$MYIPS" -v listen="$listen" 'NR > 1 {
    lp = $3; sub(/.*:/, "", lp); pp = $4; sub(/.*:/, "", pp)
    pip = $4; sub(/:[^:]*$/, "", pip); gsub(/\[|\]/, "", pip); sub(/^::ffff:/, "", pip)
    if (pip ~ /^(127\.|::1$)/ || index(myips, " " pip " ")) next
    if (index(listen, " " lp " ")) printf "in  | %-30s | :%s\n", pip, lp
    else if (pp + 0 < low) print "out | " pip ":" pp
    else print "out | " pip }'
}
# Peers outside the test set always vanish in the isolated VNet, so a difference is shown, not failed.
judge_sessions() { check sessions infoonly; }

def synsent target 'Blocked outbound attempts'
cmd_synsent() {
  ss -tnp state syn-sent
}
proc_synsent() {
  awk 'NR > 1 {proc = ""; if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10); printf "%-30s | %s\n", $4, proc}'
}
judge_synsent() {
  local n; n=$(res target synsent | grep -c .)
  if [ "$n" -gt 0 ]; then rule INFO synsent "$n blocked: $(res target synsent | join ', ')" synsent
  else line OK synsent 'no blocked outbound'; fi
}

def domain target 'Domain / IDM dependency (expected failure)'
cmd_domain() {
  realm list
  systemctl is-active sssd
}
proc_domain() {
  sed 's/^ *//' | grep -E '^(domain-name|configured):|^(active|inactive|failed|activating|unknown)$' |
    sed -E 's/^(active|inactive|failed|activating|unknown)$/sssd \1/'
}
judge_domain() { rule INFO domain "expected to fail in the test: $(res target domain | join ', ')" domain; }

def os both 'Extra: OS and kernel'
cmd_os() {
  grep PRETTY_NAME /etc/os-release; uname -r
}
proc_os() { awk 'NR == 1 {gsub(/^PRETTY_NAME=|"/, ""); print "OS " $0; next} {print "Kernel " $0}'; }
judge_os() { check os; }

def timezone both 'Extra: time zone'
cmd_timezone() {
  readlink -f /etc/localtime
}
proc_timezone() { sed 's|.*zoneinfo/||; s/^/Time zone /'; }
judge_timezone() { check timezone; }

def used both 'Extra: used space per file system'
cmd_used() {
  df -PTk -l -x tmpfs -x devtmpfs -x squashfs -x overlay
}
proc_used() { awk -v t="$TEMPDEV" 'NR > 1 && (t == "" || index($1, t) != 1) {printf "%-25s | %5d GB used\n", $7, $4 / 1048576 + 0.5}'; }
judge_used() { info used; }

def netfs both 'Extra: NFS and CIFS mounts'
cmd_netfs() {
  grep -E ' (nfs|nfs4|cifs|smb3) ' /proc/mounts
}
proc_netfs() { awk '{printf "%-25s | %s\n", $2, $1}'; }
judge_netfs() { info netfs; }

def software both 'Extra: software installed'
cmd_software() {
  rpm -qa --qf '%{NAME} | %{VERSION}-%{RELEASE}\n' 2>/dev/null || dpkg-query -W -f '${Package} | ${Version}\n'
}
proc_software() { awk -F' [|] ' '{printf "%-40s | %s\n", $1, $2}'; }
judge_software() { check software; }

def size both 'Extra: VM size'
cmd_size() {
  nproc; grep MemTotal /proc/meminfo; cat /sys/class/dmi/id/sys_vendor
}
# CPU and RAM can change with the VM size: shown, not compared.
proc_size() { awk 'NR == 1 {c = $1} /^MemTotal/ {m = int($2 / 1048576 + 0.5)} NR == 3 {v = $0} END {print c " CPU, " m " GB RAM, " v}'; }
judge_size() { info size; }

# ---------- collect ----------
collect() {
  local side=$1 virt vendor azure=0 c f s
  virt=$(systemd-detect-virt 2>/dev/null); vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)
  case "$virt $vendor" in *icrosoft*) azure=1 ;; esac
  if [ "$side" = source ] && [ $azure = 1 ]; then echo 'Stop: this is the Azure VM. Run "source" on the AVS VM.'; exit 1; fi
  if [ "$side" = target ] && [ $azure = 0 ]; then echo 'Stop: this is not the Azure VM. Run "target" on the test VM.'; exit 1; fi
  DIR="$ROOT/$side"; mkdir -p "$DIR" || exit 1
  # Results of an earlier run would otherwise survive a check that is skipped this time.
  rm -f "$DIR"/*.txt

  # Shared by several proc_ steps.
  LOW=$(awk '{print $1}' /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null); LOW=${LOW:-32768}
  MYIPS=" $(ip -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); printf "%s ", a[1]}')"
  TEMPDISK=$(readlink -f /dev/disk/azure/resource 2>/dev/null); TEMPDISK=${TEMPDISK##*/}
  TEMPDEV=""; [ -n "$TEMPDISK" ] && TEMPDEV="/dev/$TEMPDISK"

  if [ "$(id -u)" = 0 ]; then echo True; else echo False; fi | save elevated
  if [ "$(id -u)" = 0 ] || journalctl -q --no-pager -n 1 _PID=1 2>/dev/null | grep -q .; then echo True; else echo False; fi | save journal

  for c in "${CHECKS[@]}"; do
    f=${c%%|*}; s=${c#*|}; s=${s%%|*}
    [ "$s" = target ] && [ "$side" != target ] && continue
    "cmd_$f" 2>/dev/null | "proc_$f" | save "$f"
  done

  echo "$side $(hostname -s) collected $(date -u '+%Y-%m-%d %H:%M') UTC" > "$DIR/collected.txt"
  echo "Collected $side results in $DIR"
  [ "$(id -u)" = 0 ] || echo 'Not root: fine. Port owners, other users'"'"' cron jobs and maybe the journal are not visible, so those checks compare less.'
}

# ---------- compare ----------
SUM=(); DET=()
res() { [ -f "$ROOT/$1/$2.txt" ] && grep -vxF '(none)' "$ROOT/$1/$2.txt"; }
join() { awk -v s="$1" '{printf "%s%s", (NR > 1 ? s : ""), $0} END {print ""}'; }
# Result lines are padded into columns; in a one-line summary the padding only wastes the 110 characters.
line() { local l; l=$(printf '%-4s %-9s %s' "$1" "$2" "$(printf '%s' "$3" | tr -s ' ')"); SUM+=("${l:0:110}"); }
# A rule on the test VM alone: tag, name, summary text, and every line of a result file in the report.
rule() {
  local e c; line "$1" "$2" "$3"; DET+=("== $2 ($1)")
  c=$(columns "$4"); [ -n "$c" ] && res target "$4" | grep -q . && DET+=("   columns: $c")
  while IFS= read -r e; do DET+=("   $e"); done < <(res target "$4")
}
info() {
  local s t
  if [ "$SOLO" = 1 ]; then
    rule INFO "$1" "$(res target "$1" | join ', ')" "$1"; return
  fi
  s=$(res source "$1" | join ', '); t=$(res target "$1" | join ', ')
  line INFO "$1" "AVS $s -> Azure $t"; DET+=("== $1 (info)" "   AVS  : $s" "   Azure: $t")
}
# Compare one file with AVS. newonly: only what is new on Azure counts. goneonly: only what is missing
# on Azure counts. infoonly: differences are shown as INFO, not DIFF. key=n: compare only column n
# (counted from 1, split at "|"), the rest is shown. matchline: test the expected patterns on the whole
# line instead of the compared column.
check() {
  local n=$1 a newonly=0 goneonly=0 key=0 matchline=0 tag=DIFF exp sign k item l c first="" real=0 noise=0 out=()
  for a in "${@:2}"; do case $a in newonly) newonly=1 ;; goneonly) goneonly=1 ;; infoonly) tag=INFO ;;
    key=*) key=${a#key=} ;; matchline) matchline=1 ;; esac; done
  if [ "$SOLO" = 1 ]; then solo "$n" "$key" "$matchline"; return; fi
  exp=$(expected "$n")
  if [ ! -f "$ROOT/source/$n.txt" ] || [ ! -f "$ROOT/target/$n.txt" ]; then line MISS "$n" 'result file missing'; return; fi
  while IFS=$'\t' read -r sign k item; do
    [ -n "$item" ] || continue
    if [ $matchline = 1 ]; then k=$item; fi
    if [ -n "$exp" ] && printf '%s\n' "$k" | grep -qiE "$exp"; then
      noise=$((noise + 1)); out+=("   ~ expected : $sign $item")
    else
      real=$((real + 1))
      if [ "$sign" = - ]; then l="- only AVS  : $item"; else l="+ only Azure: $item"; fi
      out+=("   $l"); [ -n "$first" ] || first=$l
    fi
  done < <(
    # Prints sign <tab> compared key <tab> line, for lines whose key is not on the other side.
    only() {
      awk -F'|' -v k="$key" -v sign="$1" '
        function kk(  x) { x = (k > 0 ? $k : $0); gsub(/^ +| +$/, "", x); return x }
        FILENAME == ARGV[1] {if (length($0)) seen[kk()] = 1; next}   # NR == FNR breaks when that file is empty
        length($0) && !(kk() in seen) {print sign "\t" kk() "\t" $0}' <(res "$2" "$n") <(res "$3" "$n") | sort -t$'\t' -k3
    }
    [ $newonly = 1 ] || only - target source
    [ $goneonly = 1 ] || only + source target)
  DET+=("== $n : $real differences, $noise expected")
  c=$(columns "$n"); [ -n "$c" ] && [ ${#out[@]} -gt 0 ] && DET+=("   columns    : $c")
  [ ${#out[@]} -gt 0 ] && DET+=("${out[@]}")
  if [ $real -gt 0 ]; then line $tag "$n" "$real line(s), e.g. $first"
  elif [ $noise -gt 0 ]; then line PASS "$n" "($noise expected difference(s), see report)"
  else line PASS "$n" ''; fi
}
# Without AVS results (no access to the AVS VM, or a recovery point older than "source") a compared
# check is judged on the test VM alone: its lines are listed, still marked "~ expected" when they are.
# Checks in SOLO_LOOK go into the verdict's "look at" when they have unexpected lines: with no baseline,
# only the app owner can say whether they are right.
SOLO_LOOK=' errors jobs ports sessions '
solo() {
  local n=$1 key=$2 matchline=$3 exp l k tag=INFO text look=0 all=() real=() out=() apps
  exp=$(expected "$n")
  while IFS= read -r l; do
    [ -n "$l" ] || continue
    all+=("$l"); k=$l
    if [ "$matchline" = 0 ] && [ "$key" -gt 0 ]; then k=$(printf '%s\n' "$l" | cut -d'|' -f"$key" | sed 's/^ *//; s/ *$//'); fi
    if [ -n "$exp" ] && printf '%s\n' "$k" | grep -qiE "$exp"; then out+=("~ expected : $l"); else real+=("$l"); out+=("$l"); fi
  done < <(res target "$n")
  case " $SOLO_LOOK " in *" $n "*) [ ${#real[@]} -gt 0 ] && look=1 ;; esac
  units() { cut -d'|' -f2 | sed 's/^ *//; s/ (.*//' | join ', '; }
  case $n in
    failed)
      apps=$(printf '%s\n' "${real[@]}" | grep '^APP?')
      if [ -n "$apps" ]; then tag=FAIL; text="$(printf '%s\n' "$apps" | grep -c .) app unit(s) failed: $(printf '%s\n' "$apps" | units)"
      elif [ ${#real[@]} -gt 0 ]; then text="${#real[@]} unit(s) failed: $(printf '%s\n' "${real[@]}" | units)"
      else tag=OK; text='no failed unit'; [ ${#all[@]} -gt 0 ] && text="$text (${#all[@]} expected)"; fi ;;
    services)
      text="$(printf '%s\n' "${all[@]}" | grep -c '^AGENT') agent(s), $(printf '%s\n' "${all[@]}" | grep -c '^APP?') app service(s)" ;;
    ports) text="${#all[@]} listening" ;;
    jobs) text="${#all[@]} job(s)" ;;
    software) text="${#all[@]} package(s)" ;;
    *)
      if [ ${#all[@]} -eq 0 ]; then text=none
      elif [ ${#all[@]} -le 3 ]; then text=$(printf '%s\n' "${all[@]}" | join ', ')
      elif [ ${#real[@]} -gt 0 ]; then text="${#all[@]} line(s), e.g. $(printf '%s\n' "${real[0]}" | cut -d'|' -f1 | sed 's/ *$//')"
      else text="${#all[@]} line(s), all expected"; fi ;;
  esac
  [ $look = 1 ] && LOOK="$LOOK $n "
  line "$tag" "$n" "$text"; DET+=("== $n ($tag)")
  k=$(columns "$n"); [ -n "$k" ] && [ ${#all[@]} -gt 0 ] && DET+=("   columns: $k")
  for l in "${out[@]}"; do DET+=("   $l"); done
}
# Without root the journal is readable only for members of systemd-journal / adm / wheel:
# if one side could not read it, the Azure errors are listed, not compared.
journal_check() {
  local c
  if res source journal | grep -qx False || res target journal | grep -qx False; then
    c=$(res target "$1" | grep -c .)
    rule INFO "$1" "journal not readable on one side; $c error type(s) on Azure, see report" "$1"
  else check "$1" newonly key=1; fi
}

compare_all() {
  if [ ! -d "$ROOT/target" ]; then
    echo "No $ROOT/target: run target first, from the folder where the script is (cd there first)."; exit 1
  fi
  local c f counts bad badtag verdict legend note="" head=()
  # collected.txt is written last, so an interrupted or empty source/ also counts as no AVS results.
  SOLO=0; [ -f "$ROOT/source/collected.txt" ] || SOLO=1
  NOTCOL=(); LOOK=' '
  PARTIAL=0; { res source elevated; res target elevated; } | grep -qx False && PARTIAL=1
  if [ "$SOLO" = 1 ]; then
    res target elevated | grep -qx False && line INFO noroot "test VM run without root: port owners, other users' cron jobs and maybe the journal not visible"
  elif [ "$PARTIAL" = 1 ]; then
    line INFO noroot "run without root on $({ res source elevated | grep -qx False && echo AVS; res target elevated | grep -qx False && echo Azure; } | join ' and '): ports without owner, jobs only missing on Azure"
  fi
  for c in "${CHECKS[@]}"; do
    f=${c%%|*}
    if [ "$SOLO" = 1 ] && [ ! -f "$ROOT/target/$f.txt" ]; then NOTCOL+=("$f"); continue; fi
    "judge_$f"
  done

  if [ "$SOLO" = 1 ]; then
    head=("source $(res target collected | awk '{print $2}') not collected (no access to AVS)" "$(res target collected)")
    note='No PASS/DIFF lines: there is no AVS data to compare with.'
    legend='OK/FAIL = rule on the test VM, INFO = shown only, ~ expected = normal after the move'
    badtag='FAIL|ERR'
  else
    head=("$(res source collected)" "$(res target collected)")
    legend='PASS/DIFF = compared with AVS, OK/FAIL = rule on the test VM, INFO = shown only, ~ expected = normal after the move'
    badtag='DIFF|FAIL|MISS|ERR'
  fi
  counts=$(printf '%s\n' "${SUM[@]}" | awk '{print $1}' | sort | uniq -c | awk '{printf "%s%s %s", (NR > 1 ? ", " : ""), $1, $2}')
  bad=$(printf '%s\n' "${SUM[@]}" | awk -v t="^($badtag)\$" -v look="$LOOK" '$1 ~ t || ($1 == "INFO" && index(look, " " $2 " ")) {print $2}' | join ', ')
  if [ -n "$bad" ]; then verdict="RESULT: $counts -> look at: $bad  (migcheck.sh show <name>)"
  # Without a baseline nothing can be called "all good".
  elif [ "$SOLO" = 1 ]; then verdict="RESULT: $counts -> no FAIL, review INFO lines with the app owner"
  else verdict="RESULT: $counts -> all good, review INFO lines"; fi
  # Added after the counts: it is not a result tag.
  [ ${#NOTCOL[@]} -gt 0 ] && SUM+=("NOT COLLECTED  $(printf '%s\n' "${NOTCOL[@]}" | join ', ')")

  { printf '%s\n' "${head[@]}"; echo "$legend"; [ -n "$note" ] && echo "$note"
    echo; printf '%s\n' "${SUM[@]}"; echo "$verdict"; echo; printf '%s\n' "${DET[@]}"; } > "$ROOT/report.txt"
  # Run Command keeps only the last 4 KB of output, so the verdict goes last.
  printf '%s\n' "${head[@]}"; [ -n "$note" ] && echo "$note"; printf '%s\n' "${SUM[@]}"; echo "Detail: $ROOT/report.txt"; echo "$verdict"
}

# Report sections start with "== <name>", so one check can be printed without the rest.
show_report() {
  local rp="$ROOT/report.txt"
  [ -f "$rp" ] || { echo "No $rp yet: run target or compare first."; exit 1; }
  if [ -z "$NAME" ]; then
    # Details first and summary last: Run Command keeps the end of the output if it is too long.
    local names; names=" $(grep -E '^(INFO|DIFF|FAIL|MISS|ERR)[[:space:]]' "$rp" | awk '{printf "%s ", $2}')"
    awk -v list="$names" '/^== / {p = index(list, " " $2 " ") > 0} p' "$rp"
    echo; grep -E '^(INFO|DIFF|FAIL|MISS|ERR)[[:space:]]|^NOT COLLECTED|^RESULT:' "$rp"; return
  fi
  if grep -q "^== $NAME[ :]" "$rp"; then awk -v n="$NAME" '/^== / {p = ($2 == n)} p' "$rp"
  else echo "No check '$NAME' in the report. Names: $(awk '/^== / {print $2}' "$rp" | join ', ')"; fi
}

case "$MODE" in
  source)  collect source ;;
  target)  collect target; compare_all ;;
  compare) compare_all ;;
  show)    show_report ;;
esac
