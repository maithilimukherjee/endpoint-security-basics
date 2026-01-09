# endpoint security basics

a beginner-friendly endpoint security project built using python, focusing on defensive cybersecurity concepts.

this project demonstrates how weak passwords and malicious background activity can pose risks to endpoint systems, and how basic detection and prevention techniques can be implemented programmatically.

---

## features

* password strength analysis based on length, character diversity, and common weak patterns
* secure password hashing using bcrypt with automatic salting
* heuristic-based keylogger detection through:

  * process behavior analysis
  * filesystem monitoring for suspicious logging activity
* structured security report generation
* ethical, defensive-only implementation

---

## tech stack

* python
* bcrypt (password hashing)
* psutil (process monitoring)
* watchdog (filesystem monitoring)

---

## project structure

```
endpoint-security-basics/
│
├── app.py
├── password_checker/
│   ├── strength.py
│   └── hash_utils.py
├── keylogger_detection/
│   ├── process_scan.py
│   └── file_monitor.py
├── security_notes.md
├── requirements.txt
└── README.md
```

---

## how it works

1. evaluates password strength using entropy-related factors and known weak patterns
2. securely hashes the password using bcrypt (plaintext passwords are never stored)
3. scans running processes for suspicious characteristics commonly associated with keyloggers
4. monitors filesystem activity to detect abnormal logging behavior
5. generates a combined endpoint security report

---

## how to run

1. clone the repository
2. install dependencies:

   ```
   pip install -r requirements.txt
   ```
3. run the application:

   ```
   python app.py
   ```

the tool will output a structured endpoint security report in the terminal.

---

## security concepts demonstrated

* password entropy and attack surface reduction
* brute-force, dictionary, and credential stuffing risks
* secure credential handling using hashing and salting
* heuristic-based malware detection
* endpoint monitoring fundamentals

---

## limitations

* detection is heuristic-based and may produce false positives
* advanced or kernel-level keyloggers are outside the scope of this project
* filesystem monitoring duration is intentionally limited for performance

---

## ethical disclaimer

this project is strictly for educational and defensive cybersecurity purposes.
it does not perform exploitation, keystroke capture, or malicious activity of any kind.

---

## learning outcome

this project was built to gain hands-on experience with fundamental endpoint security principles and to understand how real-world threats can be detected and mitigated using ethical security practices.
