from password_checker.strength import check_strength
from password_checker.hash_utils import hash_password
from keylogger_detection.process_scan import scan_processes
from keylogger_detection.file_monitor import monitor_files


def run_security_check(password):
    report = {}

    # password analysis
    password_report = check_strength(password)
    report["password_security"] = password_report

    # hashing (demonstration only)
    hashed_password = hash_password(password)
    report["password_hashed"] = True  # never expose hash

    # keylogger detection
    process_alerts = scan_processes()
    file_alerts = monitor_files(duration=5)

    report["endpoint_threats"] = {
        "suspicious_processes": process_alerts,
        "suspicious_files": file_alerts
    }

    return report


if __name__ == "__main__":
    test_password = "Password123!"
    security_report = run_security_check(test_password)

    print("\nendpoint security report\n")
    for section, details in security_report.items():
        print(section, ":", details)
