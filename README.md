
# PhantomClean Elite - Ghost Protocol v3.1

> Advanced Stealth Cleanup Utility for Windows Environments  
> **Author**: Donwell  
> **Improvements by**: Kilo Code  
> **Original**: `EnhancedCleanup_v1.3.bat`  
> **Version**: 3.1 - *Ghost Protocol*

---

## 🧠 Overview

**PhantomClean Elite** is an advanced Windows batch script designed for deep-cleaning, stealth operations, and system telemetry control. Built with red team operations, sandbox evasion, and memory-only execution in mind, it provides a robust framework for evasion, persistence, and secure C2 communication.

---

## ⚙️ Features

- 🧹 **Temp & VBS File Cleanup**  
- 🧠 **Anti-Debugger & Anti-Sandbox Countermeasures**  
- 🔒 **Memory-only Execution Support**  
- 🧬 **C2 Beaconing (Configurable)**  
- 🔁 **Persistence Mechanisms**  
- 💣 **Self-Destruct Protocol**  
- 🪞 **Decoy Mode Activation** when analysis tools or VMs are detected  
- 📊 **Verbose Logging (Optional)**  

---

## 🔧 Configuration Parameters

All configurable options are defined at the top of the script:

| Variable | Purpose |
|---------|---------|
| `CFG_TARGET_TEMP_PATH` | Path to clean `.vbs` files (default: `%SystemRoot%\Temp`) |
| `CFG_VBS_PATTERN` | File pattern to target during cleanup |
| `CFG_LOG_VERBOSE` | Enable/Disable verbose console logs |
| `CFG_C2_URL` | Secure Command & Control endpoint |
| `CFG_ENABLE_C2` | Enable C2 communication (`true`/`false`) |
| `CFG_PERSISTENCE_ENABLED` | Install persistence mechanisms |
| `CFG_SLEEP_TIMER_MS` | Randomized delay using system entropy |
| `CFG_ENCRYPTION_SEED` | Timestamp-based encryption seed |
| `CFG_SELF_DESTRUCT_ENABLED` | Enable post-execution self-deletion |
| `CFG_SANDBOX_CHECK_ENABLED` | Enable sandbox detection |
| `CFG_ANTI_DEBUG_ENABLED` | Enable debugger detection |
| `CFG_MEMORY_ONLY_EXECUTION` | Execute without leaving files on disk |
| `CFG_DECOY_MODE_ACTIVE` | Activate dummy behavior in suspicious environments |

---

## 🛡️ Security Features

### Anti-Debugger Checks
Detects tools such as:
- `ollydbg.exe`
- `ida.exe`
- `procexp.exe`
- `wireshark.exe`
- `fiddler.exe`

### Sandbox Evasion
- Low uptime detection
- Low RAM threshold
- Low CPU core count
- Virtualization keyword match in `systeminfo`

### Self-Destruct
- Deletes the script after execution if enabled
- Optionally leaves no disk artifact (`memory-only` mode)

---

## 📡 C2 Communication

If enabled, the script attempts to beacon to a remote URL:

```
CFG_C2_URL=https://secure-cdn-domain.net/api/v2/telemetry
```

You can replace the URL with your own listener endpoint.

---

## 🗃️ Persistence

If persistence is enabled, the script will attempt to install itself to maintain execution across reboots. This includes:
- Registry Run entries
- Scheduled tasks
- Hidden copy to `AppData` or `%TEMP%`

---

## 🚫 Disclaimer

This tool is **for educational and authorized red team use only**. Use of this tool on unauthorized systems may violate laws and regulations. The author assumes **no responsibility** for misuse or damages.

---

## 👤 Author

- **Donwell** - [@Jackdonwel](https://github.com/Jackdonwel)  
- Enhanced implementation and security hardening by **Kilo Code**

---

## 🧩 Notes

- Avoid running this script in uncontrolled environments.
- Requires **Administrator** privileges to function properly.
- All operations can be traced in verbose mode if `CFG_LOG_VERBOSE=true`.

---

## 📄 License

MIT License — Free to use with attribution. Do not remove author credits.
