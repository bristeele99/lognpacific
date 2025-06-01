# 🕵️‍♀️ Incident Report – *Operation: Phantom Hackers at Acme Corp*

## Courtesy of the CyberRange Hosting this CTF and @TrevinoParker7 for making this CTF

> At Acme Corp, eccentric IT admin **Bubba Rockerfeatherman III** unknowingly becomes the target of a covert APT group: **The Phantom Hackers 👤**. As the digital guardian of trillions in digital assets, Bubba’s account is now the entry point into Acme’s most valuable secrets.
>
> The Phantom Hackers have infiltrated the network using phishing, credential theft, and stealthy malware. Your mission is to hunt through Defender telemetry, identify malicious artifacts, trace execution paths, and stop the breach before it’s too late.

---

### ✅ Known Info:

* **DeviceName:** `anthony-001`
* **Initial Alert Time:** `2025-05-17T00:06:32Z`

---

## 🛡️ **Flag 1: Identify the Fake Antivirus Program Name**

**🎯 Objective:**
Determine the name of the suspicious or deceptive antivirus program that initiated the security incident.

**🔍 What to Hunt:**
Look for a suspicious file or binary resembling antivirus software.

**🧠 Thought:**
Attribution begins here — recognizing the core malware is key to understanding the rest of the attack chain.

**💡 Hints:**

1. Platform we use in our company
2. Program name likely begins with A, B, or C
3. Contains

```kql
let specifiedDate = datetime(2025-05-17T00:06:32Z);
DeviceFileEvents
| where DeviceName == "anthony-001"
| where Timestamp between ((specifiedDate - 15d) .. (specifiedDate + 15d))
| where FileName startswith "A" or "B" or "C"
| where InitiatingProcessAccountDomain == "anthony-001"
```

📁 Suspicious File Found:

* `BitSentinelCore.exe` — fake AV pretending to be legit

📌 **Flag 1 Answer:** `BitSentinelCore.exe`

---

## 🛠️ **Flag 2: Malicious File Written Somewhere**

**🎯 Objective:**
Confirm that the fake AV binary was dropped to disk.

**🔍 What to Hunt:**
Find the binary write event and the dropper responsible.

**🧠 Thought:**
Helps verify malware delivery vectors and behaviors.

**💡 Hints:**

1. Legit software
2. Microsoft
3. Three

```kql
DeviceFileEvents
| where FileName == "BitSentinelCore.exe"
```

📎 Dropped By: `csc.exe` — likely abused by malware or a packer.

📌 **Flag 2 Answer:** `csc.exe`

---

## ⚙️ **Flag 3: Execution of the Program**

**🎯 Objective:**
Determine how and when the malware was executed.

**🔍 What to Hunt:**
Process events showing the binary running.

**🧠 Thought:**
Execution marks when the infection officially starts.

**💡 Hint:**
Bubba clicked the .exe himself.

```kql
DeviceProcessEvents
| where FileName == "BitSentinelCore.exe"
```

📌 **Flag 3 Answer:** `BitSentinelCore.exe`

---

## 🎯 **Flag 4: Keylogger Artifact Written**

**🎯 Objective:**
Identify if a keylogger-like artifact was written.

**🔍 What to Hunt:**
Check for file writes that indicate monitoring/surveillance.

**🧠 Thought:**
Evidence of credential theft or spying.

**💡 Hints:**

1. “A rather efficient way...”
2. News

```kql
DeviceFileEvents
| where FileName == "systemreport.lnk"
```

📁 Found in: Hidden subfolder under `ThreatMetrics`

📌 **Flag 4 Answer:** `systemreport.lnk`

---

## 🧬 **Flag 5: Registry Persistence Entry**

**🎯 Objective:**
Find persistence via Windows Registry.

**🔍 What to Hunt:**
Look for startup registry key entries referencing the malware.

**🧠 Thought:**
Persistence ensures malware survives reboot.

**💡 Hint:**
Long answer

```kql
DeviceRegistryEvents
| where RegistryValueData has "BitSentinelCore.exe"
```

📌 **Flag 5 Answer:**
`HKEY_CURRENT_USER\S-1-5-21-2009930472-1356288797-1940124928-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

---

## ⏰ **Flag 6: Daily Scheduled Task Created**

**🎯 Objective:**
Prove the attacker wanted **long-term access**.

**🔍 What to Hunt:**
Identify the scheduled task created by the malware.

**🧠 Thought:**
Without this, the infection might look like a one-off event.

**💡 Hints:**

1. Three
2. Fitness

```kql
DeviceProcessEvents
| where ProcessCommandLine has "UpdateHealthTelemetry"
```

📌 **Flag 6 Answer:** `UpdateHealthTelemetry`

---

## 🔗 **Flag 7: Process Spawn Chain**

**🎯 Objective:**
Understand the execution chain that led to persistence.

**🔍 What to Hunt:**
Trace the process relationship: Parent ➝ Child ➝ Grandchild

**🧠 Thought:**
Shows how the malware orchestrated long-term execution.

**💡 Hint:**
Use format: `parent -> child -> grandchild`

```text
BitSentinelCore.exe -> cmd.exe -> schtasks.exe
```

📌 **Flag 7 Answer:** `BitSentinelCore.exe -> cmd.exe -> schtasks.exe`

---

## 🕓 **Flag 8: Timestamp Correlation**

**🎯 Objective:**
Correlate the first event to the entire chain.

**🔍 What to Hunt:**
Find the timestamp of the first triggering event.

**🧠 Thought:**
Builds a strong forensic timeline of events.

```kql
DeviceFileEvents
| where FileName == "BitSentinelCore.exe"
```

📌 **Flag 8 Answer:** `2025-05-07T02:00:36.794406Z`

---

### ✅ Case Summary:

We've successfully followed the Phantom Hackers’ footprints and exposed their stealthy campaign. From dropper to scheduled task, registry persistence, and even the keylogger—every part of Bubba’s digital fortress was almost lost.

But not today.
**Mission accomplished. 💼🔍🛡️**