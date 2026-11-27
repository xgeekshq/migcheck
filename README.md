# migcheck

Read-only checks for VM migrations. Collects a baseline on the source VM, checks the migrated copy against it and flags only real differences: disks, network, services, ports, TLS, logs. Windows (PowerShell) and Linux (bash). Built for AVS to Azure test migrations.

## Use

**1. Source (AVS VM), before the recovery point you will test from.** The results then travel to Azure on the VM's own disk.

```powershell
# Windows, elevated prompt. Script must live in C:\migcheck (or pass -Root)
powershell -NoProfile -ExecutionPolicy Bypass -File C:\migcheck\migcheck.ps1 source
```
```bash
# Linux, no sudo needed. Results go in the current folder (or pass --root DIR)
cd ~/migcheck && bash migcheck.sh source
```

Wait for a recovery point newer than the time in `source/collected.txt`, then run the test migration.

**2. Target (Azure test VM).** Portal > VM > Run command, or a session on the VM.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File C:\migcheck\migcheck.ps1 target -Peers 10.1.2.3:1433,app2.fqdn:443
```
```bash
cd /home/<user>/migcheck && bash migcheck.sh target --peers 10.1.2.3:1433,app2.fqdn:443
```

`--peers` / `-Peers` is optional (inter-tier test). The last line, `RESULT`, says all good or which checks to look at.

**3. Read the details.**

```
migcheck show             INFO and problem details, verdict last
migcheck show <check>     one check in full, e.g. show services
migcheck compare          re-run the comparison only
```

Full report: `report.txt` next to the script.

## Reading the summary

| Tag | Meaning |
|---|---|
| PASS / DIFF | compared with the source |
| OK / FAIL | rule checked on the target alone |
| INFO | shown, not judged |
| `~ expected` | difference normal after the move (VMware → Azure, isolated test VNet); not counted as DIFF |

## Gotchas

- **Order matters.** If `source` ran after the recovery point, the target has no `source/` folder and stops. Re-run source, wait for a newer point, test-migrate again.
- **Platform guard.** `source` refuses to run on Azure and `target` refuses to run anywhere else (detected via the Microsoft hypervisor / manufacturer).
- **Run Command shows only the last 4 KB.** The verdict is printed last; use `show <check>` to read the rest piece by piece.
- **Linux Run Command starts in another folder**: always `cd` to the script folder first.
- **Without root / elevation** a few checks see less (port owners, other users' crontabs, scheduled tasks, shares, TLS bindings, journal). The scripts adapt and add a `noroot` INFO line; run elevated on the source for the fullest baseline.
- **Windows line endings.** If bash says `$'\r': command not found`: `sed -i 's/\r$//' migcheck.sh`.
- Domain / IdM, NTP, DNS, KMS and update-server failures are expected in an isolated test network and reported as INFO or `~ expected`.

`Manual-Checks-Linux.txt` and `Manual-Checks-Windows.txt` hold every check as a standalone command, with what is normal on each side, for running one by hand or digging into a report line.

## Beyond AVS to Azure

These scripts can be improved to contemplate any migration scenario, given that they are executed in a source VM, that VM may be migrated and we may use the script in the target VM. The AVS/Azure specifics are isolated: the platform guard in `collect`, the `expected` patterns (`MOVE`, `NOIDM`, ... / `$Move`, `$NoDC`, ...) and the few target-only checks (Azure agent, Hyper-V drivers, temporary disk).

## Roadmap

- **`.gitattributes`** (`*.sh text eol=lf`, `*.ps1 text eol=crlf`) so line endings never break the bash script.
- **Configurable scenario**, e.g. `--from vmware --to azure`, with the expected-difference patterns in one profile file per scenario. Today the platform guard is just "Microsoft hypervisor or not", so an on-prem Hyper-V source is mistaken for Azure.
- **`--force`** to skip the platform guard (nested virtualisation, Azure-to-Azure moves).
- **Same non-admin handling in both scripts.** Bash reduces checks if either side ran without root; PowerShell only looks at the source, so a non-admin Windows target can report false DIFFs.
- **CI**: `shellcheck` and `PSScriptAnalyzer` on every push, plus a test that compares two saved result sets and checks the report.
- **Machine-readable output**: a JSON summary next to `report.txt`, and a non-zero exit code on DIFF / FAIL, so a migration wave can be gated automatically.
- **Wave runner**: run `target` over Run Command for every VM in a wave and gather the `RESULT` lines into one table.
- **More checks**
  - Linux: SELinux / AppArmor mode, `/etc/hosts`, `sysctl` settings, firewall rules.
  - Windows: page file location (often moves to the temporary disk), firewall profile, installed hotfixes.
- **LICENSE and owner**, if shared outside the team.
