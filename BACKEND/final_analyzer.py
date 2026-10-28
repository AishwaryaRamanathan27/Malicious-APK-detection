from androguard.core.bytecodes import apk
import os
import json
from datetime import datetime

def analyze_apk(apk_path):
    print(f"\n{'='*60}")
    print(f"Analyzing: {os.path.basename(apk_path)}")
    print('='*60)
    
    try:
        # Load APK
        a = apk.APK(apk_path)
        
        # Get basic info
        package = a.get_package()
        version = a.get_androidversion_name() or "Unknown"
        
        # Get all permissions
        permissions = a.get_permissions()
        
        print(f"\n📦 Package: {package}")
        print(f"📌 Version: {version}")
        print(f"\n📋 Total permissions: {len(permissions)}")
        
        # Show all permissions
        if permissions:
            print("\n🔍 Permission list:")
            for i, perm in enumerate(sorted(permissions), 1):
                print(f"  {i:2d}. {perm}")
        
        # Calculate risk score
        high_risk_keywords = ['READ_CONTACTS', 'SEND_SMS', 'CAMERA', 'RECORD_AUDIO', 
                             'ACCESS_FINE_LOCATION', 'READ_SMS', 'CALL_PHONE']
        
        high_risk_count = 0
        for perm in permissions:
            if any(keyword in perm for keyword in high_risk_keywords):
                high_risk_count += 1
        
        risk_score = min(high_risk_count * 15, 100)
        
        if risk_score < 30:
            risk_level = "LOW"
        elif risk_score < 60:
            risk_level = "MEDIUM"
        elif risk_score < 85:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"
        
        print(f"\n📊 Risk Score: {risk_score} - {risk_level}")
        print(f"⚠️  High risk permissions: {high_risk_count}")
        
        return {
            'fileName': os.path.basename(apk_path),
            'packageName': package,
            'version': version,
            'permissions': permissions,
            'totalPermissions': len(permissions),
            'highRiskPermissions': high_risk_count,
            'riskScore': risk_score,
            'riskLevel': risk_level,
            'scanDate': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

# Test with your Facebook APK
apk_file = r"E:\Malicious APK\BACKEND\com.facebook.lite_499.0.0.9.106-513301137_minAPI26(arm64-v8a)(nodpi)_apkmirror.com.apk"
result = analyze_apk(apk_file)

if result:
    print("\n" + "="*60)
    print("✅ ANALYSIS COMPLETE")
    print(json.dumps(result, indent=2))