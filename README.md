# Home SOC Lab — Detection Engineering with Wazuh

A hands-on home Security Operations Center (SOC) built to practice **detection engineering** and **purple teaming**: deploy a SIEM, collect meaningful endpoint telemetry, write custom detections mapped to MITRE ATT&CK®, and validate them by emulating real attacker techniques — then find and close the gaps the tests expose.

---

## Overview

This project builds a working SIEM pipeline and uses it the way a real detection engineer does: not just "set it up," but **run attacks against it, see what the detections miss, understand *why*, and improve them.** Three attacker techniques were emulated with Atomic Red Team; each one taught a different detection lesson, and two of them exposed real gaps that were closed with new custom rules.

**Key outcomes**
- Stood up a Wazuh SIEM with an enrolled Windows 11 endpoint.
- Layered telemetry: Windows event logs → Sysmon process data → PowerShell Script Block Logging.
- Wrote and deployed custom detection rules mapped to MITRE ATT&CK.
- Validated detections through adversary emulation and **closed two detection gaps** discovered in the process.
- Applied false-positive tuning (allowlisting known-good admin activity).

---

## Lab Architecture

| Component | Role |
|---|---|
| **Wazuh Manager** (Linux VM) | SIEM — collects telemetry, evaluates rules, raises alerts, hosts the dashboard |
| **Windows 11** (VM) | Monitored endpoint — runs the Wazuh agent + Sysmon |
| **Attacker tooling** | Atomic Red Team (run locally on the endpoint to emulate techniques) |

```
                 +------------------------+
                 |   Wazuh Manager (SIEM) |
                 |   rules + dashboard    |
                 +-----------^------------+
                             | agent traffic (1514/1515)
                             |
                 +-----------+------------+
                 |   Windows 11 Endpoint  |
                 |   Wazuh Agent          |
                 |   + Sysmon             |
                 |   + PowerShell logging |
                 +------------------------+
```

> **Note:** Hosts run as isolated VMs. Real IP addresses/hostnames have been replaced with placeholders in this document — do not commit internal IPs, agent keys, or other secrets to a repository.

---

## Build Summary

1. **Deploy Wazuh Manager** from the official all-in-one OVA image.
2. **Enroll the Windows agent** — registered with `agent-auth` pointing at the manager IP; configured the manager address in the agent's `ossec.conf`.
3. **Install Sysmon** on the endpoint for rich process-creation telemetry (and more).
4. **Enable PowerShell Script Block Logging** (records the *code PowerShell actually executes*, not just how it was launched).
5. **Wire the channels into the agent** by adding `<localfile>` entries in `ossec.conf` for the Sysmon and PowerShell operational channels, then restarting the agent.

---

## Telemetry Sources

Detection is only as good as the data collected, so telemetry was added in layers — each one unlocking visibility the previous layer lacked.

| Source | Example Event IDs | What it reveals |
|---|---|---|
| Windows Security log | 4624 / 4625 | Successful / failed logons |
| **Sysmon** | 1 (process create), 13 (registry) | Programs launched, full command lines, parent process |
| **PowerShell Script Block Logging** | 4104 | The actual script content executed — including in-memory code |

---

## Custom Detection Rules

All custom rules live in `/var/ossec/etc/rules/local_rules.xml` on the manager (IDs in the 100000+ custom range).

### Rule 100100 — PowerShell download cradle (command line) — `T1059.001`
Detects a PowerShell process launched with a download method on its **command line**, excluding an approved scripts path.

```xml
<rule id="100100" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe|\\pwsh\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)DownloadString|DownloadFile|Invoke-WebRequest|iwr|wget|curl</field>
  <field name="win.eventdata.commandLine" type="pcre2" negate="yes">(?i)\\AdminScripts\\</field>
  <description>PowerShell download cradle detected</description>
  <mitre><id>T1059.001</id></mitre>
</rule>
```

### Rule 100110 — PowerShell in-memory cradle (script block) — `T1059.001`
Detects a download cradle run **in memory** (via `IEX`), which rule 100100 cannot see because it never appears on a command line. Reads the executed script-block content instead.

```xml
<rule id="100110" level="12">
  <if_sid>91837</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)DownloadString|DownloadFile|Invoke-WebRequest|Net\.WebClient|iwr</field>
  <description>Suspicious PowerShell script block - in-memory download cradle</description>
  <mitre><id>T1059.001</id></mitre>
</rule>
```

### Rule 100120 — certutil LOLBin download — `T1105`
Detects `certutil.exe` (a legitimate certificate tool) being abused to download files. Keys on the download sub-commands (`urlcache` / `verifyctl`) rather than any URL, to reduce false positives.

```xml
<rule id="100120" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\certutil\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)urlcache|verifyctl</field>
  <description>Certutil LOLBin download detected</description>
  <mitre><id>T1105</id></mitre>
</rule>
```

### Rule 100500 — Tuning: suppress known-good admin logins
Lowers routine SSH logins from the admin workstation to level 0 (recorded, not alerted) while still alerting on logins from **any other** source.

```xml
<rule id="100500" level="0">
  <if_sid>5501,5502</if_sid>
  <srcip>ADMIN_WORKSTATION_IP</srcip>
  <description>Admin login from known workstation - suppressed</description>
</rule>
```

---

## Adversary Emulation & Findings

Each technique was run with Atomic Red Team, then investigated in Wazuh using the loop: **run → did a detection fire? → why / why not? → improve → re-test.**

### 1. T1059.001 — PowerShell Download Cradle  →  *gap found & closed*

- **Ran:** a download cradle that pulls a script and executes it in memory (`IEX (New-Object Net.WebClient).DownloadString(...)`).
- **Finding:** command-line rule **100100 did not fire.**
- **Root cause:** the cradle ran **in memory via `IEX`** inside an existing PowerShell session — no new process was created with the payload on its command line, so process-creation telemetry had nothing to match. (A directly-launched `powershell.exe -Command "...DownloadString..."` *was* caught, confirming the rule works — the difference is purely *how* the code was delivered.)
- **Fix:** enabled **Script Block Logging** and added rule **100110**, which reads the executed script content. The same attack was then detected.
- **Lesson:** command-line detection is blind to in-memory execution. This is a deliberate attacker evasion, and it requires a different telemetry source to catch.

### 2. T1105 — Ingress Tool Transfer (certutil)  →  *gap found & closed*

- **Ran:** `certutil -urlcache -split -f <url> <outfile>` — downloading a file with a trusted Windows binary.
- **Finding:** rules 100100/100110 **missed it entirely** — they only watch PowerShell, and this was `certutil`.
- **Fix:** added rule **100120** to detect certutil being used as a downloader (a "LOLBin" — Living Off the Land Binary).
- **Lesson:** attackers abuse trusted, pre-installed tools to avoid bringing malware. Detection means spotting **trusted tools doing untrusted things**, not just watching for known-bad programs.

### 3. T1033 — System Owner/User Discovery  →  *deliberate "no dedicated rule" decision*

- **Ran:** `whoami /all` (reconnaissance).
- **Finding:** the activity was **logged** (visible in Sysmon Event 1) but produced no recon-specific alert — only generic "abnormal cmd parent" alerts fired, reacting to *how* it launched, not *what* it did.
- **Decision:** **not** to write a dedicated single-event rule. `whoami` is extremely common; alerting on every instance would bury real signal in noise.
- **Lesson:** not every attacker action warrants a signature. Recon is better caught through **context** (unusual parent/account) or **correlation** (a *burst* of discovery commands in seconds). Knowing when *not* to add a rule is itself a detection-engineering skill.

---

## Key Lessons

- **Telemetry is the foundation.** Each layer (logons → process data → script-block content) unlocked detections the previous layer couldn't support.
- **Where you detect matters.** Command-line vs. in-memory execution are different detection surfaces; covering a technique from multiple angles is more robust than one rule.
- **LOLBins are a core modern problem.** Trusted binaries (`certutil`, and others like `bitsadmin`, `rundll32`, `mshta`) are abused precisely because they look normal.
- **More rules ≠ better.** Noisy detections erode trust; tuning and correlation are as important as writing new rules.
- **Validate everything.** Emulation proves a detection works (or doesn't), and a suppression rule should be re-tested to confirm it actually suppresses.

---

## Skills Demonstrated

SIEM deployment and administration (Wazuh) · agent enrollment · endpoint telemetry (Sysmon, PowerShell Script Block Logging) · custom detection rule authoring · MITRE ATT&CK mapping · adversary emulation (Atomic Red Team) · purple-team workflow · false-positive tuning / allowlisting · log analysis and triage · Linux server administration and troubleshooting.

---

## MITRE ATT&CK Coverage

| Technique | Name | Rule(s) |
|---|---|---|
| T1059.001 | Command and Scripting Interpreter: PowerShell | 100100, 100110 |
| T1105 | Ingress Tool Transfer | 100120 |
| T1033 | System Owner/User Discovery | (context/correlation — no dedicated rule by design) |

---

## Future Work

- **Linux endpoint monitoring** (auditd / Sysmon for Linux) — a monitored Linux box, not just the SIEM server.
- **Broader ATT&CK coverage** — persistence (Run keys, scheduled tasks), credential access (LSASS), defense evasion (log clearing, registry tampering), and other LOLBins.
- **Correlation rules** — e.g., alert on a *burst* of discovery commands rather than single events.
- **Chained attacks from a separate attacker host (Kali)** — full kill-chain emulation (recon → payload → C2 → post-exploitation) for more realistic, end-to-end detection practice.

---

## A Note on Approach

This project was built as a hands-on learning exercise, using an AI assistant as a tutor and pair-debugger. I used it to learn *by doing* — not to have the work done for me. I made (and caught) real mistakes along the way: XML typos that stopped the manager from starting, a snapshot restore that wiped my setup, a custom rule that didn't fire because of rule precedence, and a false-positive risk in my certutil rule that I spotted and tightened myself. At each step I focused on understanding *why* something worked, not just *what* to type — and I can explain every rule and design decision in this repo. The goal was to build real detection-engineering intuition, and the troubleshooting was part of the learning, not a detour around it.

---

*Built as a learning project to develop practical detection-engineering skills. All testing was performed against isolated lab VMs that I own.*
