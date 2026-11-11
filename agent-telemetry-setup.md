# Endpoint Telemetry Setup (Windows Agent)

Steps and config used to give the Wazuh agent rich detection telemetry on the
Windows endpoint. Run PowerShell commands in an **Administrator** shell.

---

## 1. Sysmon (process-creation and more)

Install Sysmon with a configuration, then confirm the service is running.

```powershell
# from the folder containing the Sysmon binaries
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Sysmon logs to the channel **`Microsoft-Windows-Sysmon/Operational`**
(Event ID 1 = process creation, with full command line and parent process).

---

## 2. PowerShell Script Block Logging (Event 4104)

Records the actual code PowerShell executes — including in-memory code run via
`IEX` that never appears on a command line.

```powershell
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1
```

Logs to the channel **`Microsoft-Windows-PowerShell/Operational`** (Event ID 4104).

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
| `data.win.system.eventID:4104` | PowerShell script-block events |

Once both return results, the endpoint is feeding the detections in
`rules/local_rules.xml`.
