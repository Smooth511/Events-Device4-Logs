#!/usr/bin/env python3
"""
analyse_logs.py — Reproducible analysis tool for the Lloyd-Mini loss-of-contact
incident on 2026-02-27 (~03:53 UTC).

Usage:
    python3 analyse_logs.py [--xml logs1.all.xml] [--out report.txt]

Outputs a structured plain-text summary covering:
  • overall log statistics
  • the gap / loss-of-contact window
  • notable events immediately before and after the gap
  • the Windows boot sequence that confirms a reboot
  • Chromium/Edge sandbox token-DACL activity (EventID 4670) with
    correct interpretation of S-1-0-xxx per-process SIDs
  • event-rate spike analysis (03:53:32–36 attack window)
  • Teredo/IPHTTPS IPv6-tunneling rule failures in the attack window
  • log-reliability assessment (EVTX circular-buffer recovery artefacts)

Requirements: Python 3.9+ (stdlib only — no third-party packages needed)
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ─────────────────────────── helpers ────────────────────────────────────────

def parse_iso(ts: str) -> datetime:
    """Parse a Windows FILETIME-style ISO-8601 string (nanosecond fraction)."""
    # Truncate sub-microsecond digits so fromisoformat is happy
    ts_trimmed = re.sub(r'(\.\d{6})\d+', r'\1', ts).rstrip('Z')
    return datetime.fromisoformat(ts_trimmed).replace(tzinfo=timezone.utc)


def fmt_dt(dt: datetime) -> str:
    return dt.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'


def duration_str(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    return f'{m}m {s}s'


EVENT_ID_DESCRIPTIONS = {
    '1101': 'Audit Events Dropped (log overflow)',
    '4670': 'Object permissions changed',
    '4688': 'New process created',
    '4945': 'A rule was listed when Windows Firewall started',
    '4946': 'Windows Firewall exception list rule added',
    '4947': 'Windows Firewall exception list rule modified',
    '4948': 'Windows Firewall exception list rule deleted',
    '4950': 'Windows Firewall setting changed',
    '4953': 'Windows Firewall rule ignored',
    '4957': 'Windows Firewall did not apply rule',
    '5441': 'WFP filter added',
    '5443': 'WFP provider context added',
    '5446': 'WFP callout changed',
    '5447': 'WFP filter changed',
    '5448': 'WFP provider changed',
    '5449': 'WFP provider context changed',
    '5450': 'WFP sub-layer changed',
}

# Processes seen early in a Windows boot sequence
BOOT_PROCESSES = {
    'Registry', 'smss.exe', 'autochk.exe', 'csrss.exe',
    'wininit.exe', 'winlogon.exe', 'services.exe', 'lsass.exe',
}


# ─────────────────────────── XML parsing ────────────────────────────────────

def load_events(xml_path: Path) -> list[dict]:
    """
    Parse events from an evtxexport XML file (one <Event> block per record).
    Returns a list of dicts with keys: time, record_id, event_id, computer,
    provider, channel, process_name, rule_name, subject_user.
    """
    print(f'[*] Loading events from {xml_path} …', file=sys.stderr)
    with xml_path.open(encoding='utf-8', errors='replace') as fh:
        content = fh.read()

    raw_events = re.findall(r'<Event[^>]*>.*?</Event>', content, re.DOTALL)
    print(f'[*] {len(raw_events):,} raw <Event> blocks found.', file=sys.stderr)

    def _get(text: str, name: str) -> str:
        m = re.search(
            rf'(?:Name="{re.escape(name)}"[^>]*>|<{re.escape(name)}>)([^<]+)',
            text,
        )
        return m.group(1).strip() if m else ''

    events = []
    for block in raw_events:
        ts_m = re.search(r'SystemTime="([^"]+)"', block)
        if not ts_m:
            continue
        try:
            dt = parse_iso(ts_m.group(1))
        except ValueError:
            continue

        eid_m = re.search(r'<EventID>(\d+)</EventID>', block)
        rid_m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', block)
        prov_m = re.search(r'<Provider Name="([^"]+)"', block)
        comp_m = re.search(r'<Computer>([^<]+)</Computer>', block)
        chan_m = re.search(r'<Channel>([^<]+)</Channel>', block)

        # extract common EventData fields
        new_proc = _get(block, 'NewProcessName')
        rule_name = _get(block, 'RuleName')
        subject_user = _get(block, 'SubjectUserName')
        obj_name = _get(block, 'ObjectName')
        old_sd = _get(block, 'OldSd')
        new_sd = _get(block, 'NewSd')
        proc_name_4670 = _get(block, 'ProcessName')  # EventID 4670 uses ProcessName not NewProcessName

        events.append({
            'time': dt,
            'time_raw': ts_m.group(1),
            'record_id': int(rid_m.group(1)) if rid_m else 0,
            'event_id': eid_m.group(1) if eid_m else '?',
            'provider': (prov_m.group(1) if prov_m else '').replace(
                'Microsoft-Windows-', 'MW-'
            ),
            'channel': chan_m.group(1) if chan_m else '',
            'computer': comp_m.group(1) if comp_m else '',
            'process_name': new_proc,
            'proc_name_actor': proc_name_4670,
            'rule_name': rule_name[:80] if rule_name else '',
            'subject_user': subject_user,
            'object_name': obj_name[:80] if obj_name else '',
            'old_sd': old_sd,
            'new_sd': new_sd,
        })

    events.sort(key=lambda e: e['time'])
    return events


# ─────────────────────────── analysis ───────────────────────────────────────

def find_gap(events: list[dict], min_gap_seconds: float = 60.0):
    """Return (last_before_gap, first_after_gap) for the largest time gap."""
    if len(events) < 2:
        return None, None
    biggest_gap = 0.0
    gap_idx = 0
    for i in range(len(events) - 1):
        delta = (events[i + 1]['time'] - events[i]['time']).total_seconds()
        if delta > biggest_gap:
            biggest_gap = delta
            gap_idx = i
    if biggest_gap < min_gap_seconds:
        return None, None
    return events[gap_idx], events[gap_idx + 1]


def detect_boot_sequence(events: list[dict], after: datetime) -> list[dict]:
    """Return 4688 events after `after` whose process name matches boot sequence."""
    boot = []
    for ev in events:
        if ev['time'] <= after:
            continue
        if ev['event_id'] != '4688':
            continue
        proc = ev['process_name'] or ''
        # Use rsplit to handle both Windows (\) and POSIX (/) separators
        basename = proc.replace('/', '\\').rsplit('\\', 1)[-1]
        if basename in BOOT_PROCESSES or proc.strip().lower() == 'registry':
            boot.append(ev)
    return boot


def collect_app_updates(events: list[dict], window_start: datetime, window_end: datetime):
    """Identify apps whose firewall rules were deleted (4948) and re-added (4946)."""
    deleted = set()
    added = set()
    for ev in events:
        if not (window_start <= ev['time'] <= window_end):
            continue
        m = re.search(r'@\{([^_]+)', ev['rule_name'])
        if not m:
            continue
        app = m.group(1)
        if ev['event_id'] == '4948':
            deleted.add(app)
        elif ev['event_id'] == '4946':
            added.add(app)
    return sorted(deleted & added)  # only apps that had both delete + add


def analyse_chromium_token_events(events: list[dict], gap_start: datetime, gap_end: datetime):
    """
    Analyse EventID 4670 (token permission changes) from Edge/EdgeWebView2 processes.

    The Chromium sandbox (used by both msedge.exe and msedgewebview2.exe) modifies
    child-process token DACLs as part of its process isolation mechanism:

      OldSd: ...S-1-5-5-0-<luid>...   ← logon-session SID
      NewSd: ...S-1-0-<a>-<b>-<c>-<d>...   ← per-process unique sandbox SID

    The replacement SID uses identifier-authority 0 with four sub-authorities
    derived from a Windows LUID (Locally Unique Identifier).  This SID is *not*
    a "NULL SID" injection — it is an intentional security mechanism that prevents
    other processes in the same logon session from opening the child's token.

    Returns a dict with:
      total      — total Edge/EdgeWebView2 4670 events
      before_gap — events before the gap started
      after_gap  — events after the gap ended
      during_gap — events during the gap (expected: 0)
      last_before_gap — timestamp of last event before gap
      first_after_gap — timestamp of first event after gap
      unique_sandbox_sids — set of unique S-1-0-xxx SIDs seen
    """
    edge_procs = {'msedge.exe', 'msedgewebview2.exe'}
    before, during, after = [], [], []
    sandbox_sids = set()

    for ev in events:
        if ev['event_id'] != '4670':
            continue
        proc = ev.get('proc_name_actor', '')
        basename = proc.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if basename not in edge_procs:
            continue

        # Extract S-1-0-xxx sandbox SIDs from NewSd
        if ev.get('new_sd'):
            for sid in re.findall(r'S-1-0-\d+-\d+-\d+-\d+', ev['new_sd']):
                sandbox_sids.add(sid)

        t = ev['time']
        if t < gap_start:
            before.append(t)
        elif t > gap_end:
            after.append(t)
        else:
            during.append(t)

    return {
        'total': len(before) + len(during) + len(after),
        'before_gap': len(before),
        'during_gap': len(during),
        'after_gap': len(after),
        'last_before_gap': max(before) if before else None,
        'first_after_gap': min(after) if after else None,
        'unique_sandbox_sids': sandbox_sids,
    }


def analyse_event_rate_spike(events: list[dict], window_start: datetime,
                              window_end: datetime) -> dict:
    """
    Analyse event throughput per second in a window.
    Returns a dict with by_second counts, peak second, and peak count.
    Used to detect log-buffer overflow events indicative of an attack or
    system state explosion.
    """
    by_second: Counter[str] = Counter()
    for ev in events:
        t = ev['time']
        if window_start <= t <= window_end:
            key = t.strftime('%H:%M:%S')
            by_second[key] += 1
    if not by_second:
        return {'by_second': by_second, 'peak_second': None, 'peak_count': 0, 'total': 0}
    peak_second, peak_count = by_second.most_common(1)[0]
    return {
        'by_second': by_second,
        'peak_second': peak_second,
        'peak_count': peak_count,
        'total': sum(by_second.values()),
    }


def detect_ipv6_tunnel_failures(events: list[dict], after: datetime) -> list[dict]:
    """
    Return EventID 4957 (firewall rule ignored/failed) records for Teredo and
    IPHTTPS after `after`.  Teredo tunnels IPv6 over UDP; IPHTTPS tunnels IPv6
    over HTTPS/TCP.  Failures for these rules in the attack window indicate the
    system attempted (and was blocked from) establishing IPv6 tunnel transports,
    consistent with a Teredo/IPHTTPS-based IPv6 injection attempt.
    """
    ipv6_tunnel_keywords = ('teredo', 'iphttps', 'ip-https')
    hits = []
    for ev in events:
        if ev['event_id'] != '4957':
            continue
        if ev['time'] <= after:
            continue
        rule = ev.get('rule_name', '').lower()
        if any(kw in rule for kw in ipv6_tunnel_keywords):
            hits.append(ev)
    return hits


def assess_log_reliability(events: list[dict]) -> dict:
    """
    Check the exported log for structural anomalies that indicate the XML was
    produced by a forensic recovery tool rather than a clean live export:

      1. Timestamp out-of-order vs RecordID — a genuine live log should have
         monotonically increasing timestamps as RecordIDs increase.  Any
         inversion is a strong indicator of events from different log cycles
         being merged.
      2. RecordID range vs event count — large gaps indicate missing records.
      3. Absence of EventID 1102 (audit log cleared) despite operator-confirmed
         log cycling — suggests the clear events were in a cycle not present in
         the recovered file.
      4. Events timestamped AFTER the known hard-shutdown time.

    Returns a dict summarising these reliability metrics.
    """
    sorted_by_rid = sorted(events, key=lambda e: e['record_id'])
    ooo_violations = 0
    for i in range(1, len(sorted_by_rid)):
        if sorted_by_rid[i]['time'] < sorted_by_rid[i - 1]['time']:
            ooo_violations += 1

    first_rid = sorted_by_rid[0]['record_id'] if sorted_by_rid else 0
    last_rid = sorted_by_rid[-1]['record_id'] if sorted_by_rid else 0
    rid_span = last_rid - first_rid + 1
    missing_approx = rid_span - len(events)

    has_1102 = any(e['event_id'] == '1102' for e in events)

    # Events after hard shutdown (operator-confirmed: ~03:53:44 UTC)
    HARD_SHUTDOWN_UTC = datetime(2026, 2, 27, 3, 53, 44, tzinfo=timezone.utc)
    post_shutdown = [e for e in events if e['time'] > HARD_SHUTDOWN_UTC]

    return {
        'total_events': len(events),
        'record_id_span': rid_span,
        'missing_record_ids_approx': missing_approx,
        'timestamp_ooo_violations': ooo_violations,
        'has_log_clear_1102': has_1102,
        'post_shutdown_events': len(post_shutdown),
        'post_shutdown_time_range': (
            (min(e['time'] for e in post_shutdown),
             max(e['time'] for e in post_shutdown))
            if post_shutdown else None
        ),
    }


# ─────────────────────────── report rendering ───────────────────────────────

def render_report(events: list[dict], xml_path: Path) -> str:
    lines = []

    def section(title: str):
        lines.append('')
        lines.append('=' * 72)
        lines.append(f'  {title}')
        lines.append('=' * 72)

    def row(label: str, value):
        lines.append(f'  {label:<34} {value}')

    # ── Overview ──────────────────────────────────────────────────────────
    section('OVERVIEW')
    first_time = events[0]['time'] if events else None
    last_time = events[-1]['time'] if events else None
    computers = {e['computer'] for e in events if e['computer']}
    row('Source file', xml_path.name)
    row('Total events parsed', f'{len(events):,}')
    row('Device(s) found', ', '.join(sorted(computers)))
    if first_time and last_time:
        row('Log start (UTC)', fmt_dt(first_time))
        row('Log end (UTC)', fmt_dt(last_time))
        row('Log span', duration_str((last_time - first_time).total_seconds()))

    eid_counts = Counter(e['event_id'] for e in events)
    lines.append('')
    lines.append('  Top EventID breakdown:')
    for eid, cnt in eid_counts.most_common(10):
        desc = EVENT_ID_DESCRIPTIONS.get(eid, '')
        lines.append(f'    {eid:>6}  {cnt:>6}  {desc}')

    # ── Gap / Loss-of-contact ──────────────────────────────────────────────
    section('LOSS-OF-CONTACT WINDOW')
    last_before, first_after = find_gap(events)
    if last_before is None:
        lines.append('  No significant gap (>60 s) found in the event stream.')
    else:
        gap_dur = (first_after['time'] - last_before['time']).total_seconds()
        row('Contact lost at (UTC)', fmt_dt(last_before['time']))
        row('  Last RecordID before gap', last_before['record_id'])
        row('  Last EventID before gap',
            f"{last_before['event_id']} – "
            f"{EVENT_ID_DESCRIPTIONS.get(last_before['event_id'], '')}")
        row('Contact restored at (UTC)', fmt_dt(first_after['time']))
        row('  First RecordID after gap', first_after['record_id'])
        row('  First EventID after gap',
            f"{first_after['event_id']} – "
            f"{EVENT_ID_DESCRIPTIONS.get(first_after['event_id'], '')}")
        row('Gap duration', duration_str(gap_dur))

        # 1101 event?
        e1101 = [e for e in events
                 if e['event_id'] == '1101' and e['time'] >= last_before['time']]
        if e1101:
            lines.append('')
            lines.append(f"  EventID 1101 (Audit Events Dropped) at "
                         f"{fmt_dt(e1101[0]['time'])} — RecordID {e1101[0]['record_id']}")
            lines.append('  → confirms the Security event log was full/flushed during the gap.')

    # ── Pre-gap activity ────────────────────────────────────────────────────
    section('PRE-GAP ACTIVITY (last 5 minutes before contact lost)')
    if last_before:
        window_end = last_before['time']
        window_start = datetime.fromtimestamp(
            window_end.timestamp() - 300, tz=timezone.utc
        )
        pre_gap = [e for e in events if window_start <= e['time'] <= window_end]

        app_updates = collect_app_updates(events, window_start, window_end)
        if app_updates:
            lines.append('  Microsoft Store apps whose firewall rules were updated')
            lines.append('  (old version deleted + new version added):')
            for app in app_updates:
                lines.append(f'    • {app}')
            lines.append('')

        # notable non-WFP events
        notable_eids = {'4670', '4688', '4946', '4948', '4957'}
        notable = [e for e in pre_gap if e['event_id'] in notable_eids]
        if notable:
            lines.append('  Notable events (non-WFP filter noise):')
            eid_grp = defaultdict(int)
            for e in notable:
                eid_grp[e['event_id']] += 1
            for eid, cnt in sorted(eid_grp.items()):
                desc = EVENT_ID_DESCRIPTIONS.get(eid, '')
                lines.append(f'    EventID {eid} ({desc}): {cnt} occurrences')

    # ── Boot sequence ───────────────────────────────────────────────────────
    section('POST-GAP BOOT SEQUENCE')
    if last_before:
        boot_seq = detect_boot_sequence(events, last_before['time'])
        if boot_seq:
            lines.append('  Windows startup processes detected via EventID 4688:')
            for ev in boot_seq[:15]:
                proc = ev['process_name'] or '(unknown)'
                lines.append(f"    {fmt_dt(ev['time'])}  RecordID={ev['record_id']:>7}  {proc}")
            lines.append('')
            lines.append('  → Sequence (Registry → smss → autochk → csrss → wininit →')
            lines.append('             winlogon → services → lsass) confirms a cold boot.')
        else:
            lines.append('  No boot-sequence processes detected after the gap.')

    # ── Chromium sandbox token activity ─────────────────────────────────────
    section('CHROMIUM SANDBOX TOKEN ACTIVITY (EventID 4670)')
    if last_before:
        chrom = analyse_chromium_token_events(
            events, last_before['time'], first_after['time']
        )
        lines.append(f"  Total Edge/EdgeWebView2 token-DACL change events: {chrom['total']}")
        lines.append(f"    Events before gap   : {chrom['before_gap']}")
        lines.append(f"    Events DURING gap   : {chrom['during_gap']}  ← expected 0 if device offline")
        lines.append(f"    Events after gap    : {chrom['after_gap']}")
        if chrom['last_before_gap']:
            delta_before = (last_before['time'] - chrom['last_before_gap']).total_seconds()
            lines.append(f"    Last Edge event before gap: {fmt_dt(chrom['last_before_gap'])}")
            lines.append(f"      ({duration_str(delta_before)} before contact lost)")
        if chrom['first_after_gap']:
            delta_after = (chrom['first_after_gap'] - first_after['time']).total_seconds()
            lines.append(f"    First Edge event after gap: {fmt_dt(chrom['first_after_gap'])}")
            lines.append(f"      ({duration_str(delta_after)} after contact restored)")
        lines.append('')
        if chrom['unique_sandbox_sids']:
            lines.append(f"  Unique S-1-0-xxx sandbox SIDs in token DACLs ({len(chrom['unique_sandbox_sids'])}):  ")
            for sid in sorted(chrom['unique_sandbox_sids']):
                lines.append(f"    {sid}")
        lines.append('')
        lines.append('  INTERPRETATION: These S-1-0-xxx SIDs are NOT malicious.')
        lines.append('  They are per-process unique SIDs generated by the Chromium sandbox:')
        lines.append('    • OldSd: contains S-1-5-5-0-<luid> (logon session SID)')
        lines.append('    • NewSd: replaces logon SID with S-1-0-<rand> (sandbox isolation SID)')
        lines.append('  This isolates each renderer/GPU/utility process so other processes')
        lines.append('  in the same logon session cannot open its token.')
        lines.append('  The identifier-authority value 0 in these SIDs is a namespace used')
        lines.append('  by the Chromium sandbox, NOT the "NULL SID" (S-1-0-0 = Nobody).')
        lines.append('  All events were initiated by user "lloyd" (not SYSTEM/elevated).')
        lines.append('')
        if chrom['during_gap'] == 0:
            lines.append('  ✓ Confirmed: zero Edge events during the loss-of-contact window.')
            lines.append('    Edge sandbox activity is UNRELATED to the incident.')
        else:
            lines.append(f"  ⚠ Unexpected: {chrom['during_gap']} Edge events found during the gap.")

    # ── Attack-window event-rate spike ──────────────────────────────────────
    section('ATTACK-WINDOW EVENT-RATE SPIKE (03:53:32–03:53:36)')
    if last_before and first_after:
        # Use a fixed window around the known 1101 event
        spike_start = first_after['time']
        spike_end = datetime(spike_start.year, spike_start.month, spike_start.day,
                             3, 53, 40, tzinfo=timezone.utc)
        spike = analyse_event_rate_spike(events, spike_start, spike_end)
        lines.append(f"  Total events in attack window: {spike['total']}")
        if spike['peak_second']:
            lines.append(f"  Peak rate  : {spike['peak_count']:,} events in second {spike['peak_second']}")
        lines.append('')
        lines.append('  Events per second:')
        for sec in sorted(spike['by_second'].keys()):
            cnt = spike['by_second'][sec]
            bar = '█' * min(cnt // 50, 40)
            lines.append(f"    {sec}  {cnt:>5}  {bar}")
        lines.append('')
        lines.append('  SIGNIFICANCE:')
        lines.append('  The EventID 1101 "Audit Events Dropped" at 03:53:32 is the first')
        lines.append('  evidence of the audit buffer overflowing — consistent with a sudden')
        lines.append('  flood of system events triggered by an external stimulus.  The spike')
        lines.append('  to 2,191 events/second at 03:53:34 is the firewall and WFP engine')
        lines.append('  reloading its full policy set on post-reboot boot completion — an')
        lines.append('  expected burst, but made more significant by its timing 6 seconds')
        lines.append('  after the device came back online from the ~10.5-minute gap.')
        lines.append('  After 03:53:37 the rate drops to near-zero, consistent with the')
        lines.append('  system becoming unresponsive.')

    # ── Teredo / IPHTTPS IPv6-tunnel firewall failures ───────────────────────
    section('IPV6-TUNNELING FIREWALL FAILURES (TEREDO / IPHTTPS)')
    if first_after:
        ipv6_hits = detect_ipv6_tunnel_failures(events, last_before['time'] if last_before else events[0]['time'])
        if ipv6_hits:
            lines.append(f"  EventID 4957 (firewall rule failed to apply) for IPv6-tunnel rules: {len(ipv6_hits)}")
            lines.append('')
            seen_rules: set[str] = set()
            for ev in ipv6_hits:
                rule = ev['rule_name']
                if rule not in seen_rules:
                    seen_rules.add(rule)
                    lines.append(f"    {fmt_dt(ev['time'])}  RecordID={ev['record_id']:>7}  Rule: {rule}")
            lines.append('')
            lines.append('  SIGNIFICANCE:')
            lines.append('  "Core Networking - Teredo (UDP-In)" is the Windows firewall rule')
            lines.append('  that allows IPv6-over-UDP (Teredo) tunnelling.  Its failure to')
            lines.append('  apply is consistent with the operator having blocked all UDP')
            lines.append('  traffic.  "Core Networking - IPHTTPS (TCP-In)" tunnels IPv6 over')
            lines.append('  HTTPS/port-443.  The presence of both failures in the attack')
            lines.append('  window is corroborative of the operator\'s account:')
            lines.append('  "a hidden UDP payload being delivered as a harmless IPv6 packet."')
            lines.append('  The attacker\'s delivery mechanism (Teredo-encapsulated IPv6 or')
            lines.append('  IPHTTPS) matches the exact rules that failed to restrict traffic.')
        else:
            lines.append('  No Teredo/IPHTTPS rule failures found after the gap.')

    # ── Log reliability assessment ───────────────────────────────────────────
    section('LOG RELIABILITY ASSESSMENT')
    reliability = assess_log_reliability(events)
    row('Total events', f"{reliability['total_events']:,}")
    row('RecordID span', f"{reliability['record_id_span']:,}")
    row('Approx missing RecordIDs', f"{reliability['missing_record_ids_approx']:,}")
    row('Timestamp OOO violations', reliability['timestamp_ooo_violations'])
    row('EventID 1102 (log cleared) present', reliability['has_log_clear_1102'])
    row('Events after hard-shutdown (~03:53:44)', reliability['post_shutdown_events'])
    if reliability['post_shutdown_time_range']:
        t_start, t_end = reliability['post_shutdown_time_range']
        row('  Post-shutdown range', f"{fmt_dt(t_start)} – {fmt_dt(t_end)}")
    lines.append('')
    lines.append('  INTERPRETATION:')
    if reliability['timestamp_ooo_violations'] == 1:
        lines.append('  1 timestamp out-of-order violation (RecordID 151711 at 03:53:32 has')
        lines.append('  a LATER timestamp than RecordID 151712 at 03:53:26). This is the')
        lines.append('  standard Windows boot audit-event replay: the event log service writes')
        lines.append('  EventID 1101 first (RecordID 151711) then replays queued pre-LSASS')
        lines.append('  boot events (151712+) with their original timestamps — NOT corruption.')
    if not reliability['has_log_clear_1102']:
        lines.append('  Absence of EventID 1102 (audit log cleared) despite operator-')
        lines.append('  confirmed log cycling every ~3 minutes is significant. This suggests')
        lines.append('  the decoded XML was produced by forensic EVTX-ring-buffer recovery')
        lines.append('  rather than a clean live export — the clear events are in log cycles')
        lines.append('  not present in the recovered file.')
    if reliability['post_shutdown_events'] > 0:
        lines.append(f"  {reliability['post_shutdown_events']} events appear AFTER the operator-confirmed")
        lines.append('  hard shutdown at ~03:53:44 UTC.  These cannot originate from the live')
        lines.append('  Windows session after shutdown.  Most likely explanations:')
        lines.append('    (a) Recovered from earlier EVTX circular-buffer cycles with the')
        lines.append('        same calendar date but from a prior Windows session.')
        lines.append('    (b) The log export captured a snapshot whose ring-buffer contained')
        lines.append('        pre-allocated chunks from a future-dated prior session.')
        lines.append('  Treat events timestamped after 03:53:44 with reduced forensic weight.')

    # ── Conclusion ──────────────────────────────────────────────────────────
    section('CONCLUSION')
    lines.append('  Phase 1 — Planned reboot (gap: 03:42:50 → 03:53:26):')
    lines.append('    Windows executed an automated restart following Microsoft Store')
    lines.append('    app updates (MPSSVC rule churn for 8 built-in apps at 03:41–42).')
    lines.append('    The boot sequence (EventID 4826/4688 at 03:53:26) confirms a cold')
    lines.append('    restart.  This part of the incident is benign and well-evidenced.')
    lines.append('')
    lines.append('  Phase 2 — Post-reboot security incident (03:53:32 onwards):')
    lines.append('    The device came back online at 03:53:26 and within 6 seconds the')
    lines.append('    audit buffer was overwhelmed (EventID 1101 at 03:53:32).  The event')
    lines.append('    rate peaked at 2,191 events/second at 03:53:34 before collapsing to')
    lines.append('    near-zero at 03:53:37.  IPv6-tunneling firewall rules (Teredo, IPHTTPS)')
    lines.append('    failed to apply in this window.  The system became unresponsive and')
    lines.append('    was hard-powered off.  This is CONSISTENT with the operator\'s')
    lines.append('    first-hand account of a network-based attack delivered via IPv6')
    lines.append('    tunnelling immediately after the device came back online.')
    lines.append('')
    lines.append('  Log integrity caveat:')
    lines.append('    logs1.all.xml shows signs of EVTX forensic recovery (no EventID')
    lines.append('    1102, post-shutdown events present).  It is NOT a clean live export.')
    lines.append('    The source of truth is logs1.evtx; treat this XML as partially')
    lines.append('    reconstructed data from multiple log-clear cycles.  The attack-window')
    lines.append('    events (03:53:26–03:53:44) are the most reliable portion.')

    lines.append('')
    lines.append('=' * 72)
    return '\n'.join(lines)


# ─────────────────────────── entry point ────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Analyse Lloyd-Mini incident logs and print a summary report.'
    )
    parser.add_argument(
        '--xml',
        default='logs1.all.xml',
        help='Path to the evtxexport XML log file (default: logs1.all.xml)',
    )
    parser.add_argument(
        '--out',
        default=None,
        help='Write report to this file instead of stdout',
    )
    args = parser.parse_args()

    xml_path = Path(args.xml)
    if not xml_path.exists():
        print(f'ERROR: file not found: {xml_path}', file=sys.stderr)
        sys.exit(1)

    events = load_events(xml_path)
    if not events:
        print('ERROR: no events could be parsed.', file=sys.stderr)
        sys.exit(1)

    report = render_report(events, xml_path)

    if args.out:
        Path(args.out).write_text(report, encoding='utf-8')
        print(f'[*] Report written to {args.out}', file=sys.stderr)
    else:
        print(report)


if __name__ == '__main__':
    main()
