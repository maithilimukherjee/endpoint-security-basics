## project scope

this project focuses on basic endpoint security techniques suitable for beginners.

### components
1. password security analysis
   - password strength evaluation
   - exposure to breached credentials (without storing passwords)

2. keylogger detection
   - process behavior analysis
   - file system monitoring for suspicious logging activity

## threat model (basic)

- attackers may attempt to steal credentials using keyloggers
- weak passwords increase the risk of brute-force and credential stuffing attacks
- this project focuses on detection and prevention, not exploitation

## limitations

- heuristic-based detection may produce false positives
- advanced or kernel-level keyloggers are outside the scope of this project
- filesystem monitoring duration is limited for performance reasons
