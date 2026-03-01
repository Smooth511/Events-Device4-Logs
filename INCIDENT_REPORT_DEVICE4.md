# Assessment of Alternate Incident Report — Device 4 (Lloyd-Mini)
**Assessment date:** 2026-03-01  
**Assessor:** Independent log review  
**Subject report:** "Investigation Complete" report claiming system compromise  
**Verdict: DISAGREE — the alternate report's security findings are incorrect**

---

## 1. Summary

A separate analysis agent produced a report claiming that `Lloyd-Mini` suffered
a security compromise driven by `msedgewebview2.exe` "injecting invalid NULL
Security Identifiers" into process tokens, and that this was the probable cause
of the 2026-02-27 loss-of-contact event.

**This assessment disagrees with every major security claim in that report.**

The evidence from the logs supports only one conclusion: the device experienced
a **planned, automated Windows reboot** triggered by Microsoft Store / Windows
Update completing installation of 8 built-in app updates. The
EdgeWebView2/msedge token-modification events are benign, standard Chromium
sandbox activity that is temporally unrelated to the incident.

---

## 2. Point-by-Point Rebuttal

### Claim A: "Critical Security Finding — EdgeWebView2 injecting invalid NULL SIDs"

> *"The device experienced anomalous token manipulation activity where the
> Microsoft EdgeWebView2 process (msedgewebview2.exe) was injecting invalid NULL
> Security Identifiers (S-1-0-xxx) into process token security descriptors."*

**INCORRECT.**

The EventID 4670 records from `msedgewebview2.exe` and `msedge.exe` show the
Chromium sandbox performing its standard **process-token DACL restriction**:

| Field | Value | Meaning |
|---|---|---|
| EventID | 4670 | Object permissions changed |
| SubjectUserName | `lloyd` | Standard non-elevated user |
| ObjectType | Token | Process access token |
| OldSd | `…(A;;GXGR;;;S-1-5-5-0-354768)` | Contains logon-session SID |
| NewSd | `…(A;;GA;;;S-1-0-xxx-xxx-xxx-xxx)…` | Logon SID replaced by sandbox SID |

The Chromium browser sandbox is well-documented ([source][1]). When spawning a
renderer, GPU, or utility child process it:
1. Calls `CreateRestrictedToken()` to harden the child's access token.
2. Replaces the logon-session SID (`S-1-5-5-0-<luid>`) with a per-process
   unique SID derived from a Windows LUID (`AllocateLocallyUniqueId`).
3. The resulting SID uses identifier-authority `0` with four sub-authorities —
   an opaque private namespace chosen by Chromium.

This is a **security feature**, not an attack. Its purpose is exactly the
opposite of what the alternate report claims: it *restricts* access to the
child process's token rather than granting it.

[1]: https://chromium.googlesource.com/chromium/src/+/main/docs/design/sandbox.md

---

### Claim B: "S-1-0 prefix is the NULL SID authority and should never appear in legitimate token DACLs"

**INCORRECT.**

The SID `S-1-0-0` is the standard "Nobody" SID and is legitimate in Windows.
However, claiming the identifier-authority value `0` "should never appear" in
DACLs conflates the well-known Nobody SID with arbitrary SIDs that happen to
use authority `0`. There is no Windows policy that prohibits applications from
using authority `0` for their own SID namespaces.

The specific SIDs seen (`S-1-0-113147267-…`, `S-1-0-1650355308-…`, etc.) each
have **four sub-authorities** (unlike `S-1-0-0` which has one), confirming
they are application-generated process-isolation SIDs, not the Nobody SID.

Furthermore, `S-1-0-0` (Nobody) does legitimately appear in the log — in
`TargetUserSid` fields of early-boot 4688/4696 events (`Registry`, `smss.exe`)
where no user context has been established yet. This is standard Windows
behaviour.

---

### Claim C: "The probable cause is system compromise through the EdgeWebView2 process"

**INCORRECT — timing disproves causation.**

The loss-of-contact gap runs from **03:42:50 UTC** to **03:53:26 UTC**.

| Event | Time (UTC) | Δ from gap |
|---|---|---|
| Last EdgeWebView2 4670 before gap | **03:35:15** | 7 min 35 s **before** |
| Contact lost (last audit event) | 03:42:50 | — |
| Contact restored (first boot event) | 03:53:26 | — |
| First EdgeWebView2 4670 after gap | **03:53:52** | 26 s **after** |
| EdgeWebView2 events **during** gap | **0** | — |

There are **zero** Edge/EdgeWebView2 events during the actual gap.  The browser
stopped its sandbox activity more than 7 minutes before the device went
offline. Edge activity resumed 26 seconds after the device completed booting.
This is consistent with Edge simply being closed by the user before sleep/idle,
and restarting after the device rebooted.

No causal chain between EdgeWebView2 and the loss of contact is possible.

---

### Claim D: "Detected Malformed SIDs" (listing 5 SIDs as indicators of compromise)

**INCORRECT.**

Each of the five listed SIDs corresponds to a single Chromium child process
instance. The SIDs are unique per process (as intended — using a LUID as the
seed) and are ephemeral. They are not stored in persistent security policies;
they exist only in the token DACL of the child process for the lifetime of that
process. Logging them as "indicators of compromise" is a false positive.

| SID | Actual meaning |
|---|---|
| `S-1-0-113147267-1519095794-715387272-2850185809` | EdgeWebView2 sandbox SID, ~03:20Z |
| `S-1-0-1650355308-2408325621-503012698-2937194152` | EdgeWebView2 sandbox SID, ~03:23Z |
| `S-1-0-3460105017-2885499184-3102270867-2206445538` | EdgeWebView2 sandbox SID, ~03:53Z (post-boot) |
| `S-1-0-130827018-994964869-2702941970-2332722214` | msedge.exe sandbox SID, ~03:57Z |
| `S-1-0-4169528122-3105903461-1535511230-882767497` | EdgeWebView2 sandbox SID, ~03:58Z |

---

### Claim E: "System Stress Indicators — 7,218 filter changes"

**MISLEADING.**

The 7,218 EventID 5447 (WFP filter changed) records are entirely explained by
the MPSSVC firewall service cycling firewall rules for 8 Microsoft Store apps
during the update process. This is normal, expected activity for a batch Store
update. The count is high because each app has many per-layer filter rules.

The referenced events (Teredo, IPHTTPS, SSDP failures) are EventID 4957
("Windows Firewall did not apply rule"). These rules fail because the
corresponding network interfaces are not present in the active configuration at
the time of evaluation — another routine occurrence during firewall
re-initialisation on reboot.

---

### Claim F: "Isolate the cluster of 4 other devices"

**NOT SUPPORTED BY EVIDENCE.**

The logs contain no references to any other devices. There is no evidence of
lateral movement, network scanning, remote exploitation, or any inter-device
communication that would warrant isolating other machines. This recommendation
is based on a fabricated threat scenario.

---

## 3. Correct Root Cause

The loss of contact was caused by an **automated Windows reboot** following
Microsoft Store completing installation of 8 built-in app updates. The
evidence is:

1. **EventID 4948/4946 burst (03:41–03:42)** — MPSSVC cycled firewall rules for
   8 Store apps (rule delete + re-add for new version). This is the standard
   Windows Store update mechanism.
2. **EventID 4670 by LLOYD-MINI$ (03:40–03:41)** — machine-account permission
   changes via `services.exe`/`svchost.exe` (update staging, not EdgeWebView2).
3. **EventID 1101 at 03:53:32** — Security log buffer overflowed during
   shutdown (expected with a sudden reboot).
4. **EventID 4688 boot sequence starting 03:53:26** — Registry → smss →
   autochk → csrss → wininit → winlogon → services → lsass confirms a cold
   boot, not sleep/hibernate resume.

No indicators of malicious activity are present. No user session was active
at time of shutdown. No privilege escalation occurred. No lateral movement.

---

## 4. Recommendations Correction

| Alternate report recommendation | Assessment |
|---|---|
| Isolate cluster of 4 devices | ❌ Not warranted — no inter-device threat evidence |
| Memory acquisition and disk imaging | ❌ Not warranted — incident explained by updates |
| Analyse msedgewebview2.exe binary | ❌ Not warranted — standard signed Microsoft binary |
| Monitor for NULL SID appearances | ⚠️ Partially valid as a general hygiene measure, but **Edge sandbox SIDs are not IOCs** and must be excluded from any such monitoring rule to avoid chronic false positives |

Correct recommendations (see `incident_report_lloyd_mini_20260227.md` §5):
- Tune loss-of-contact alerts for the established maintenance window
- Export System channel logs alongside Security logs in future
- Increase Security log max size to reduce event drops on reboot

---

## 5. Artefacts

| File | Description |
|---|---|
| `logs1.all.xml` | Primary evidence — 11,959 Security audit events |
| `analyse_logs.py` | Reproducible analysis script (run to reproduce all findings) |
| `incident_report_lloyd_mini_20260227.md` | Full incident report with correct root cause |

To reproduce the analysis that disproves the alternate report's claims:

```bash
python3 analyse_logs.py --xml logs1.all.xml
```

The "CHROMIUM SANDBOX TOKEN ACTIVITY" section of that output will confirm:
- 0 Edge events during the gap
- Last Edge event 7m 35s before contact was lost
- All S-1-0-xxx SIDs are Chromium sandbox process-isolation SIDs
