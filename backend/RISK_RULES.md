# ITD Risk Rule Engine - Current Rules

The backend computes risk using a **10-minute sliding window** per agent.
Only recent events are considered, and all rules are deterministic and explainable.

---

## Signals Extracted

For each agent, the risk engine extracts these signals from recent events (with safe defaults):

- `file_writes` (default `0`)
- `usb_active` (default `False`)
- `clipboard_events` (default `0`)
- `process_count` (default `0`)
- `upload_bytes` (default `0`)
- `download_bytes` (default `0`)
- `vpn_active` (default `False`)
- `session_duration` (default `None`)
- `compliance_score` (default `None`)
- `enforcement_triggered` (default `False`)

Notes:
- Missing event types do not crash scoring; they simply contribute defaults.
- VPN/compliance are also read from `system` state if not found in events.

---

## Weighted Rules (Current)

Each matching rule adds points and appends a human-readable reason.

### Rule 1: File burst + USB (+40)

**Condition:** `file_writes > 50` and `usb_active`

**Reason:**
`High file activity with USB usage (possible data exfiltration)`

---

### Rule 2: Clipboard spike + outbound traffic (+35)

**Condition:** `clipboard_events > 20` and `upload_bytes > download_bytes`

**Reason:**
`Clipboard spike with high outbound network traffic`

---

### Rule 3: VPN + high file activity (+30)

**Condition:** `vpn_active` and `file_writes > 30`

**Reason:**
`High file activity over VPN connection`

---

### Rule 4: Process spike (+20)

**Condition:** `process_count > 20`

**Reason:**
`Unusual number of processes started`

---

### Rule 5: Network exfiltration pattern (+30)

**Condition:**
- `upload_bytes > download_bytes * 2`, or
- `download_bytes == 0` and `upload_bytes > 0`

**Reason:**
`Unusually high outbound network traffic`

---

### Rule 6: Non-compliant system with high activity (+35)

**Condition:** `compliance_score < 60` and `file_writes > 30`

**Reason:**
`High activity on non-compliant system`

---

### Rule 7: Compliance enforcement triggered (+30)

**Condition:** `enforcement_triggered == True`

**Reason:**
`System automatically enforced security policy`

---

### Rule 8: Extended session + high activity (+20)

**Condition:** `session_duration in (">120", "120+")` and `file_writes > 30`

**Reason:**
`High activity during extended session`

---

### Rule 9: Multi-signal exfil correlation (+25)

**Condition:** `usb_active` and `clipboard_events > 10` and `upload_bytes > download_bytes`

**Reason:**
`Multi-channel data exfiltration pattern detected`

---

## Scoring and Level Mapping

- Total rule points are summed.
- Score is capped at **100**.

Risk level mapping:

- **LOW**: score `< 30`
- **MEDIUM**: score `30-59`
- **HIGH**: score `60-79`
- **CRITICAL**: score `>= 80`

---

## Output Fields

The risk engine returns:

- `risk_score`
- `risk_level`
- `reasons` (list of triggered-rule explanations)

These are exposed by risk endpoints and included in `GET /api/v1/system/{agent_id}` as:

- `risk_score`
- `risk_level`
- `risk_reasons`
