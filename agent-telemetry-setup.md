# Endpoint Telemetry Setup (Windows Agent)

Steps and config used to give the Wazuh agent rich detection telemetry on the
Windows endpoint. Run PowerShell commands in an **Administrator** shell.

Telemetry was built up in layers; the Sysmon config in particular was upgraded
partway through the project (a minimal, process-only config left big blind
spots — registry and file activity were invisible until the richer config went
in).

---

## 1. Sysmon with the SwiftOnSecurity config

A bare `Sysmon64.exe -i` install only logs process creation. Installing with the
community **SwiftOnSecurity** config unlocks the events the detections actually
rely on.

```powershell
# Download the config
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\sysmonconfig.xml"

# Fresh install with the config...
.\Sysmon64.exe -accepteula -i C:\sysmonconfig.xml

# ...or apply the config to an already-installed Sysmon:
C:\Windows\Sysmon64.exe -accepteula -c C:\sysmonconfig.xml
```

Sysmon logs to **`Microsoft-Windows-Sysmon/Operational`**. Key event IDs this unlocks:

| Event ID | What it captures |
|---|---|
| 1 | Process creation (image, full command line, parent process) |
| 3 | Network connections |
| 10 | Process access (e.g. a process opening a handle to `lsass.exe`) |
| 11 | File creation |
| 13 | Registry value writes **(selective — only a curated set of keys)** |
| 22 | DNS queries |

> **Important nuance:** registry logging (Event 13) is **selective** — the config
> watches a curated set of sensitive keys, not every registry write. Some
> techniques modify keys outside that set and stay invisible. Likewise, some
> binaries are filtered from process logging to reduce noise. Telemetry coverage
> is always a curated, incomplete decision.

---

## 2. PowerShell Script Block Logging (Event 4104)

Records the actual code PowerShell executes — including in-memory code run via
`IEX` that never appears on a command line (this is what catches in-memory
download cradles that command-line logging misses).

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

Logs to **`Microsoft-Windows-PowerShell/Operational`** (Event ID 4104).

> Script Block Logging applies to PowerShell sessions started *after* it is
> enabled — open a fresh window before testing.

---

## 3. Forward the channels to Wazuh

Add these `<localfile>` blocks inside `<ossec_config>` in the agent config
(`C:\Program Files (x86)\ossec-agent\ossec.conf`), then restart the agent.

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>

<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Restart the agent:

```powershell
Restart-Service -Name Wazuh
```

---

## 4. Verify telemetry is arriving

In the Wazuh dashboard (Threat Hunting / Events), confirm each channel:

| Search | Confirms |
|---|---|
| `data.win.system.eventID:1` | Sysmon process-creation events |
| `data.win.system.eventID:13` | Sysmon registry events (after the config upgrade) |
| `data.win.system.eventID:4104` | PowerShell script-block events |

Once these return results, the endpoint is feeding the detections in
`rules/local_rules.xml`.
