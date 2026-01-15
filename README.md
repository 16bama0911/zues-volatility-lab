# Zeus Trojan -- Memory Forensics with Volatility
## Overview
This project documents a memory forensics investigation of a Windows XP system infected with the Zeus Trojan, conducted using the Volatility Framework on an Ubuntu analysis workstation. The analysis focuses on identifying hidden processes, injected code, and command-and-control (C2) behavior that evades traditional disk-based detection.

The investigation demonstrates how memory analysis can uncover advanced malware techniques such as process hiding, process injection, and legitimate process abuse.

## Enviroment
### Analysis Host
- Ubuntu Linux (VMware Workstation)
- Docker (for Volatility 2 compatibility)
  
### Target System
- Windows XP (memory image)
  
### Tools
- Volatility Framework 2 (via Docker)
- Volatility Framework 3 (initial testing)
- VMware Workstation
- SHA256 hashing utilities
  
## Evidence
- Memory Image: `zeus.vmem` (VMware memory dump)
- Acquisition Method: Provided memory image (offline forensic analysis)
- Integrity Verification: SHA256 hashing performed before and after analysis

## Methodology
### Part A -- Enviroment Setup & Evidence Handling
- Configured Ubuntu analysis VM
- Created a structured workspace for evidence, notes, and outputs
- Copied memory image into a controlled analysis directory
- Generated and recorded SHA256 hash to preserve forensic integrity

<img width="814" height="441" alt="Ubuntu 64-bit--Desktop-2026-01-12-16-01-06 - Copy" src="https://github.com/user-attachments/assets/9e7c3d9d-70e7-410e-99fe-907c99e20dcb" />

<img width="1035" height="94" alt="Ubuntu 64-bit--Desktop-2026-01-13-23-42-49" src="https://github.com/user-attachments/assets/ddb2bada-5868-47c2-bbd7-6e0de44beaa2" />


### Part B -- Process Triage
An initial process analysis was performed to identify anomalous behavior.
#### Key Findings
- A hidden process (`VMip.exe`, PID 1944) was identified using `psxview`
- The process was not visible in standard process listings, indicating an unlinked or terminated malware loader
- Legitimate Windows processes appeared normal in `cmdline` analysis
#### Conclusion
- The presence of a hidden process strongly suggested malware activity and evasion techniques.

### Part C -- Network & C2 Analysis
Network artifacts were identified using memory-based scanning.
#### Key Findings
- Outbound HTTP connections to an external IP address (`193.104.41.75`) were detected
- Network traffic originated from `svchost.exe` (PID 856)
- No direct network activity was attributed to the hidden loader process
#### Interpretation
- Zeus commonly injects into legitimate processes such as `svchost.exe` to proxy C2 communication
- This behavior aligns with known Zeus Trojan architecture

### Part D -- Code Injection Analysis
Memory injection analysis was performed using `malfind`.
#### Key Findings
- Private `PAGE_EXECUTE_READWRITE` memory regions were identified within `svchost.exe`
- An in-memory PE header (`MZ`) was detected, indicating a loaded executable payload
- A trampoline-style JMP stub was observed, consistent with execution redirection
- Attempts to dump injected regions did not produce output files, which can occur with small or protected injected regions
#### Conclusion
- The presence of injected executable memory confirms process injection, a hallmark of Zeus infections

### Part E -- Final Assessment
The combined forensic evidence confirms Zeus Trojan activity:
- Hidden malware loader (`VMip.exe`)
- Abuse of `svchost.exe` for network communication
- External HTTP-based C2 traffic
- Injected executable code residing solely in memory
- No reliance on disk-based artifacts

This case demonstrates how advanced malware can evade traditional detection and highlights the importance of memory forensics in incident response.

## Key Indicators of Compromise (IOCs)
- Hidden Process: `VMip.exe` (PID 1944)
- Injected Host Process: `svchost.exe` (PID 856)
- External IP: `193.104.41.75`
- Memory Artifacts: RWX regions, in-memory PE header (`MZ`)

## Skills Demonstrated
- Memory forensics using Volatility
- Process hiding and injection detection
- Network C2 correlation
- Evidence integrity verification (SHA256)
- Docker-based forensic tooling
- DFIR documentation and reporting

## Notes
This analysis was conducted on an offline memory image in a controlled lab environment for educational purposes.

