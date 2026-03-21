import os
import hashlib

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".bat", ".ps1", ".vbs", ".js",
    ".scr", ".dll", ".lnk"
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
DOCUMENT_EXTENSIONS = {".doc", ".docx", ".pdf", ".xls", ".xlsx", ".ppt", ".pptx", ".txt"}

def analyze_usb(mount_path: str):
    summary = {
        "total_files": 0,
        "executables": 0,
        "documents": 0,
        "archives": 0,
        "suspicious_files": [],
        "autorun_detected": False,
        "risk_score": 0
    }

    for root, dirs, files in os.walk(mount_path):
        for file in files:
            summary["total_files"] += 1

            full_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()

            # Autorun detection
            if file.lower() == "autorun.inf":
                summary["autorun_detected"] = True
                summary["risk_score"] += 50

            # Suspicious extension
            if ext in SUSPICIOUS_EXTENSIONS:
                summary["executables"] += 1
                summary["suspicious_files"].append(file)
                summary["risk_score"] += 10

            elif ext in ARCHIVE_EXTENSIONS:
                summary["archives"] += 1

            elif ext in DOCUMENT_EXTENSIONS:
                summary["documents"] += 1

    # Risk normalization
    if summary["executables"] > 5:
        summary["risk_score"] += 20

    if summary["total_files"] > 1000:
        summary["risk_score"] += 10

    return summary
