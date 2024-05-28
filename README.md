# gixecurity
gixesecurity is a suite of programs to scan your system for malware, find vulnerabilities in your system, and monitor changes to system directories.
see our software code for more information.

list of all malware scanned by **gixec**, (based on YARA):

    
**KeyloggerBehavior**: Detects suspicious behavior patterns indicative of keylogger activity on the system.

**WebShellPattern**: Identifies patterns associated with web shells, which are malicious web scripts used for unauthorized remote control.

**CryptoMiner**: Detects known signatures and patterns of cryptocurrency mining software.

**Comprehensive_RAT_Detection_Linux**: Comprehensive rule for detecting Remote Access Trojans (RATs) specifically on Linux systems.

**ExploitKitDetection3**: Identifies known patterns of exploit kits that target system vulnerabilities.

**MaliciousFileExtension**: Detects files with potentially harmful extensions commonly used by malware.

**SuspiciousProcessInjection**: Detects suspicious patterns indicative of process injection, a technique used by malware to inject code into legitimate processes.




list of changes monitored by **gixcontrol**:


-modified content

-moving from one directory to another

-delete file

-create new file

-cpu processes

-ram processes

