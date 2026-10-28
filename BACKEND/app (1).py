from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import hashlib
import time
import zipfile
import xml.etree.ElementTree as ET
import re
import json
from database import init_db, get_db_connection, save_apk_result, get_apk_by_hash, get_all_scans

# Resolve paths relative to this file so it works from any working directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, '..', 'FRONTEND')

app = Flask(__name__, static_folder=None)
CORS(app, origins="*")

UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────────
# Serve Frontend Static Files
# ─────────────────────────────────────────────
@app.route('/')
def serve_index():
    return send_from_directory(os.path.join(FRONTEND_DIR, 'HTML'), 'index.html')

@app.route('/results')
def serve_results():
    return send_from_directory(os.path.join(FRONTEND_DIR, 'HTML'), 'results.html')

@app.route('/HTML/<path:filename>')
def serve_html(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, 'HTML'), filename)

@app.route('/CSS/<path:filename>')
def serve_css(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, 'CSS'), filename)

@app.route('/JS/<path:filename>')
def serve_js(filename):
    return send_from_directory(os.path.join(FRONTEND_DIR, 'JS'), filename)

@app.route('/FRONTEND/<path:filename>')
def serve_frontend(filename):
    return send_from_directory(FRONTEND_DIR, filename)

# ─────────────────────────────────────────────
# Permission Risk Database
# ─────────────────────────────────────────────
PERMISSION_RISKS = {
    # HIGH RISK
    "android.permission.READ_SMS": ("high", "Can read all SMS messages — used by banking trojans"),
    "android.permission.SEND_SMS": ("high", "Can send SMS silently — often used for premium rate fraud"),
    "android.permission.RECEIVE_SMS": ("high", "Can intercept incoming SMS including OTPs"),
    "android.permission.READ_CALL_LOG": ("high", "Accesses full call history"),
    "android.permission.CALL_PHONE": ("high", "Can make calls without user interaction"),
    "android.permission.READ_CONTACTS": ("high", "Can harvest all contact data"),
    "android.permission.WRITE_CONTACTS": ("high", "Can modify/delete contacts"),
    "android.permission.PROCESS_OUTGOING_CALLS": ("high", "Can intercept outgoing calls"),
    "android.permission.RECORD_AUDIO": ("high", "Can secretly record microphone audio"),
    "android.permission.CAMERA": ("medium", "Can take photos/videos"),
    "android.permission.ACCESS_FINE_LOCATION": ("medium", "Precise GPS location access"),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "Can read all files on device"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "Can write files to storage"),
    "android.permission.GET_ACCOUNTS": ("medium", "Accesses device accounts (Google, etc.)"),
    "android.permission.USE_CREDENTIALS": ("high", "Can use account credentials"),
    "android.permission.AUTHENTICATE_ACCOUNTS": ("high", "Can act as account authenticator"),
    "android.permission.MANAGE_ACCOUNTS": ("high", "Can add/remove device accounts"),
    "android.permission.BIND_DEVICE_ADMIN": ("high", "Device administrator — hard to uninstall"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("medium", "Starts automatically on boot"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("medium", "Can draw over other apps — phishing risk"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("high", "Can silently install other APKs"),
    "android.permission.PACKAGE_USAGE_STATS": ("medium", "Monitors which apps are used"),
    "android.permission.FOREGROUND_SERVICE": ("low", "Can run persistent background service"),
    # LOW RISK
    "android.permission.INTERNET": ("low", "Basic internet access"),
    "android.permission.ACCESS_NETWORK_STATE": ("low", "Check network connectivity"),
    "android.permission.ACCESS_WIFI_STATE": ("low", "Check WiFi status"),
    "android.permission.VIBRATE": ("low", "Control vibration"),
    "android.permission.WAKE_LOCK": ("low", "Prevent CPU from sleeping"),
    "android.permission.FLASHLIGHT": ("low", "Control flashlight"),
}

MALICIOUS_PATTERNS = [
    (r"android\.permission\.(READ_SMS|SEND_SMS|RECEIVE_SMS)", "SMS interception capability — common in banking malware"),
    (r"android\.permission\.(BIND_DEVICE_ADMIN|REQUEST_INSTALL_PACKAGES)", "Elevated privilege abuse — common in spyware/droppers"),
    (r"android\.permission\.(READ_CONTACTS|GET_ACCOUNTS|USE_CREDENTIALS)", "Credential/contact harvesting pattern"),
    (r"android\.permission\.RECORD_AUDIO.*android\.permission\.ACCESS_FINE_LOCATION", "Surveillance combo: mic + location tracking"),
    (r"android\.permission\.SYSTEM_ALERT_WINDOW.*android\.permission\.BIND_ACCESSIBILITY_SERVICE", "Overlay attack pattern — can steal passwords"),
]

# ─────────────────────────────────────────────
# APK Analysis Engine
# ─────────────────────────────────────────────
def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def extract_permissions_from_apk(filepath):
    """Extract permissions using pyaxmlparser (handles binary XML), with regex fallback."""
    permissions = []
    package_name = "unknown"
    version = "unknown"

    # Method 1: pyaxmlparser (best — decodes binary AndroidManifest.xml)
    try:
        from pyaxmlparser import APK
        apk = APK(filepath)
        permissions = list(apk.permissions) if apk.permissions else []
        package_name = apk.packagename or "unknown"
        version = apk.version_name or "unknown"
        if permissions:
            return list(set(permissions)), package_name, version
    except Exception:
        pass

    # Method 2: Plain-text XML (debug/unsigned APKs)
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            if 'AndroidManifest.xml' in zf.namelist():
                manifest_data = zf.read('AndroidManifest.xml')
                try:
                    root = ET.fromstring(manifest_data)
                    package_name = root.get('package', 'unknown')
                    version = root.get('{http://schemas.android.com/apk/res/android}versionName', 'unknown')
                    for elem in root.iter('uses-permission'):
                        perm = elem.get('{http://schemas.android.com/apk/res/android}name', '')
                        if perm:
                            permissions.append(perm)
                    if permissions:
                        return list(set(permissions)), package_name, version
                except ET.ParseError:
                    pass

                # Method 3: Regex scan of raw binary manifest
                text = manifest_data.decode('latin-1')
                found = re.findall(r'android\.permission\.[A-Z_]+', text)
                permissions = list(set(found))
                pkg_match = re.search(r'com\.[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+', text)
                if pkg_match:
                    package_name = pkg_match.group(0)

    except zipfile.BadZipFile:
        pass
    except Exception:
        pass

    return list(set(permissions)), package_name, version

def build_permission_details(permissions):
    details = []
    for perm in permissions:
        risk, description = PERMISSION_RISKS.get(perm, ("low", "Unknown permission"))
        details.append({
            "name": perm,
            "risk": risk,
            "description": description
        })
    return details

def detect_threats(permissions):
    threats = []
    perm_string = " ".join(permissions)

    # Check known malicious patterns
    for pattern, description in MALICIOUS_PATTERNS:
        if re.search(pattern, perm_string):
            threats.append({
                "name": "Malicious Permission Pattern",
                "severity": "High",
                "description": description,
                "recommendation": "Do not install this app unless you fully trust the source."
            })

    # Specific checks
    high_risk = [p for p in permissions if PERMISSION_RISKS.get(p, ("low",))[0] == "high"]
    if len(high_risk) >= 4:
        threats.append({
            "name": "Excessive High-Risk Permissions",
            "severity": "High",
            "description": f"App requests {len(high_risk)} high-risk permissions simultaneously.",
            "recommendation": "Legitimate apps rarely need this many sensitive permissions."
        })

    if "android.permission.RECEIVE_BOOT_COMPLETED" in permissions and \
       "android.permission.INTERNET" in permissions and \
       any(p in permissions for p in ["android.permission.READ_SMS", "android.permission.READ_CONTACTS"]):
        threats.append({
            "name": "Persistent Spyware Pattern",
            "severity": "High",
            "description": "App starts on boot, connects to internet, and accesses sensitive data — classic spyware behavior.",
            "recommendation": "This combination is used by spyware. Avoid installation."
        })

    if "android.permission.REQUEST_INSTALL_PACKAGES" in permissions:
        threats.append({
            "name": "Dropper / Malware Installer",
            "severity": "High",
            "description": "App can silently install other apps — dropper malware hallmark.",
            "recommendation": "Only trusted app stores should have this permission."
        })

    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions:
        threats.append({
            "name": "Overlay Attack Risk",
            "severity": "Medium",
            "description": "App can draw over other apps — used for phishing login screens.",
            "recommendation": "Be cautious if this app asks for 'Draw over apps' permission."
        })

    return threats

def calculate_risk_score(permission_details, threats):
    score = 0
    for p in permission_details:
        if p["risk"] == "high":
            score += 12
        elif p["risk"] == "medium":
            score += 5
        else:
            score += 1

    for t in threats:
        if t["severity"] == "High":
            score += 20
        elif t["severity"] == "Medium":
            score += 10

    score = min(score, 100)
    return score

def score_to_level(score):
    if score < 30:
        return "LOW"
    elif score < 65:
        return "MEDIUM"
    else:
        return "HIGH"

def build_recommendations(permission_details, threats, risk_level):
    recs = []
    perm_names = [p["name"] for p in permission_details]

    if "android.permission.SEND_SMS" in perm_names or "android.permission.READ_SMS" in perm_names:
        recs.append("Avoid granting SMS permissions unless the app is a dedicated SMS manager.")
    if "android.permission.READ_CONTACTS" in perm_names:
        recs.append("Verify why contact access is needed — most apps don't require it.")
    if "android.permission.ACCESS_FINE_LOCATION" in perm_names:
        recs.append("Use 'Only while using the app' for location, never 'Always'.")
    if "android.permission.RECORD_AUDIO" in perm_names:
        recs.append("Grant microphone permission only when actively using voice features.")
    if risk_level == "HIGH":
        recs.append("Do NOT install this APK. Share it with a cybersecurity professional for analysis.")
        recs.append("Report this APK to Google Play Protect or your device manufacturer.")
    elif risk_level == "MEDIUM":
        recs.append("Install only from official sources. Review each permission at install time.")
    else:
        recs.append("App appears relatively safe — still review permissions during installation.")

    if not recs:
        recs.append("Always download APKs from trusted sources like the Google Play Store.")

    return recs

# ─────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────
@app.route('/analyze', methods=['POST'])
def analyze_apk():
    if 'apk' not in request.files:
        return jsonify({"error": "No APK file provided"}), 400

    file = request.files['apk']
    if not file.filename.endswith('.apk'):
        return jsonify({"error": "Only .apk files are accepted"}), 400

    start_time = time.time()
    # Use unique filename to avoid conflicts
    safe_name = f"{int(time.time())}_{file.filename}"
    filepath = os.path.join(UPLOAD_FOLDER, safe_name)
    file.save(filepath)

    try:
        # Compute hash — check cache first
        file_hash = compute_sha256(filepath)
        cached = get_apk_by_hash(file_hash)

        if cached:
            # Only use cache if it has actual permissions
            cached_result = json.loads(cached['result_json'])
            if cached_result.get('permissions') and len(cached_result['permissions']) > 0:
                cached_result['cached'] = True
                cached_result['message'] = "Result retrieved from database (previously scanned)"
                return jsonify(cached_result), 200
            # Cache had 0 permissions — re-scan and overwrite

        # Fresh analysis — file stays on disk until AFTER pyaxmlparser reads it
        permissions_raw, package_name, version = extract_permissions_from_apk(filepath)
        permission_details = build_permission_details(permissions_raw)
        threats = detect_threats(permissions_raw)
        risk_score = calculate_risk_score(permission_details, threats)
        risk_level = score_to_level(risk_score)
        recommendations = build_recommendations(permission_details, threats, risk_level)

        high_risk_perms = sum(1 for p in permission_details if p["risk"] == "high")
        critical_issues = sum(1 for t in threats if t["severity"] == "High")
        suspicious_activities = len(threats)

        elapsed = round(time.time() - start_time, 1)

        result = {
            "fileName": file.filename,
            "fileHash": file_hash,
            "packageName": package_name,
            "version": version,
            "permissions": permission_details,
            "threats": threats,
            "riskScore": risk_score,
            "riskLevel": risk_level,
            "summary": {
                "criticalIssues": critical_issues,
                "highRiskPermissions": high_risk_perms,
                "suspiciousActivities": suspicious_activities,
                "totalPermissions": len(permission_details)
            },
            "recommendations": recommendations,
            "scanInfo": {
                "duration": f"{elapsed} seconds",
                "dbVersion": "2025.04",
                "engineVersion": "v3.1.0",
                "scanDate": time.strftime("%Y-%m-%d")
            },
            "cached": False
        }

        # Save to database (overwrites previous bad cache)
        save_apk_result(
            file_hash=file_hash,
            file_name=file.filename,
            package_name=package_name,
            risk_score=risk_score,
            risk_level=risk_level,
            result_json=json.dumps(result)
        )

        return jsonify(result), 200

    finally:
        # Clean up uploaded file AFTER analysis is fully done
        if os.path.exists(filepath):
            os.remove(filepath)


@app.route('/history', methods=['GET'])
def get_history():
    """Return all previously scanned APKs."""
    scans = get_all_scans()
    return jsonify(scans), 200


@app.route('/history/<file_hash>', methods=['GET'])
def get_scan_by_hash(file_hash):
    """Retrieve a specific scan by SHA256 hash."""
    cached = get_apk_by_hash(file_hash)
    if not cached:
        return jsonify({"error": "No scan found for this hash"}), 404
    result = json.loads(cached['result_json'])
    return jsonify(result), 200


@app.route('/stats', methods=['GET'])
def get_stats():
    """Summary statistics of all scanned APKs."""
    scans = get_all_scans()
    total = len(scans)
    high = sum(1 for s in scans if s['risk_level'] == 'HIGH')
    medium = sum(1 for s in scans if s['risk_level'] == 'MEDIUM')
    low = sum(1 for s in scans if s['risk_level'] == 'LOW')
    return jsonify({
        "totalScanned": total,
        "high": high,
        "medium": medium,
        "low": low
    }), 200


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "ok", "version": "v3.1.0"}), 200


if __name__ == '__main__':
    init_db()
    print("✅ APK Security Analyzer backend running on http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)
