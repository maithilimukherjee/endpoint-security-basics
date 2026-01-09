import psutil
import os

SUSPICIOUS_KEYWORDS = [
    "keylog",
    "logger",
    "hook",
    "keyboard",
    "input"
]

SUSPICIOUS_PATHS = [
    "temp",
    "appdata",
    "local"
]


def scan_processes():
    """
    scans running processes and flags potentially suspicious ones
    based on name and execution path.
    """

    suspicious_processes = []

    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            name = (proc.info["name"] or "").lower()
            exe = (proc.info["exe"] or "").lower()

            score = 0
            reasons = []

            # name-based heuristics
            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword in name:
                    score += 2
                    reasons.append(f"suspicious process name: {keyword}")

            # path-based heuristics
            for path in SUSPICIOUS_PATHS:
                if path in exe:
                    score += 1
                    reasons.append(f"suspicious execution path: {path}")

            if score >= 3:
                suspicious_processes.append({
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "exe": proc.info["exe"],
                    "score": score,
                    "reasons": reasons
                })

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return suspicious_processes
