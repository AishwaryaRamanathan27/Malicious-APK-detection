from androguard.core.bytecodes import apk
from threat_database import get_permission_risk, check_suspicious_combinations
from datetime import datetime
import hashlib
import os

def analyze_apk_file(apk_path, detailed_scan=True, compare_permissions=True):
    print(f"\n{'='*60}")
    print(f"🔍 WEB APP ANALYZING: {os.path.basename(apk_path)}")
    print('='*60)
    
    try:
        # Load APK with androguard
        a = apk.APK(apk_path)
        print("✅ APK loaded successfully with androguard")
        
        # Get basic info
        package_name = a.get_package() or "Unknown"
        version = a.get_androidversion_name() or "Unknown"
        
        # Get all permissions
        permissions = a.get_permissions()
        print(f"📦 Package: {package_name}")
        print(f"📌 Version: {version}")
        print(f"📋 Total permissions found: {len(permissions)}")
        
        if permissions:
            print("📋 First 5 permissions:")
            for perm in permissions[:5]:
                print(f"   - {perm}")
        
        # Analyze each permission
        permission_list = []
        high_risk_count = 0
        threats = []
        
        # High risk keywords
        high_risk_keywords = [
            'READ_CONTACTS', 'SEND_SMS', 'CAMERA', 'RECORD_AUDIO', 
            'ACCESS_FINE_LOCATION', 'READ_SMS', 'CALL_PHONE',
            'READ_CALL_LOG', 'WRITE_CALL_LOG', 'ADD_VOICEMAIL',
            'BIND_ACCESSIBILITY_SERVICE', 'PROCESS_OUTGOING_CALLS'
        ]
        
        for perm in permissions:
            # Get risk info from database
            risk_info = get_permission_risk(perm)
            risk = risk_info.get('risk', 'unknown')
            
            # If unknown but matches keywords, mark as high risk
            if risk == 'unknown':
                if any(keyword in perm for keyword in high_risk_keywords):
                    risk = 'high'
                elif 'ACCESS' in perm or 'READ' in perm or 'WRITE' in perm:
                    risk = 'medium'
                else:
                    risk = 'low'
            
            permission_list.append({
                'name': perm,
                'risk': risk,
                'description': risk_info.get('description', 'Android permission')
            })
            
            if risk == 'high':
                high_risk_count += 1
                threats.append({
                    'name': f"High Risk: {perm.split('.')[-1]}",
                    'severity': 'High',
                    'description': risk_info.get('warning', f'App requests {perm.split(".")[-1]} permission'),
                    'recommendation': f'Review if this permission is necessary'
                })
        
        # Check suspicious combinations
        if compare_permissions and len(permissions) > 0:
            combo_threats = check_suspicious_combinations(permissions)
            threats.extend(combo_threats)
        
        # Calculate risk score (0-100)
        # Base score from high risk permissions
        risk_score = high_risk_count * 12
        
        # Add points for total permissions (more permissions = higher risk)
        if len(permissions) > 50:
            risk_score += 10
        elif len(permissions) > 30:
            risk_score += 5
        
        # Add points for threats
        risk_score += len(threats) * 5
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score < 30:
            risk_level = 'LOW'
        elif risk_score < 60:
            risk_level = 'MEDIUM'
        elif risk_score < 85:
            risk_level = 'HIGH'
        else:
            risk_level = 'CRITICAL'
        
        print(f"\n✅ Analysis complete!")
        print(f"📊 Risk Score: {risk_score} - {risk_level}")
        print(f"⚠️  High risk permissions: {high_risk_count}")
        print('='*60)
        
        # Build results dictionary
        results = {
            'fileName': os.path.basename(apk_path),
            'fileSize': f"{os.path.getsize(apk_path) / (1024*1024):.2f} MB",
            'packageName': package_name,
            'version': version,
            'permissions': permission_list,
            'threats': threats,
            'riskScore': risk_score,
            'riskLevel': risk_level,
            'summary': {
                'totalPermissions': len(permissions),
                'highRiskPermissions': high_risk_count,
                'criticalIssues': len(threats),
                'suspiciousActivities': len(threats)
            },
            'recommendations': [
                f"⚠️ {high_risk_count} high-risk permissions detected",
                f"📊 Risk Level: {risk_level}",
                f"📋 Total permissions: {len(permissions)}"
            ],
            'scanInfo': {
                'scanDate': datetime.now().strftime('%Y-%m-%d'),
                'engineVersion': 'Androguard v4.1.3',
                'duration': '2 seconds'
            }
        }
        
        return results
        
    except Exception as e:
        print(f"❌ Error in analyze_apk_file: {e}")
        import traceback
        traceback.print_exc()
        
        # Return error results
        return {
            'fileName': os.path.basename(apk_path),
            'error': str(e),
            'riskScore': 0,
            'riskLevel': 'ERROR',
            'permissions': [],
            'threats': [],
            'summary': {
                'totalPermissions': 0,
                'highRiskPermissions': 0,
                'criticalIssues': 0,
                'suspiciousActivities': 0
            },
            'recommendations': ['Error analyzing APK'],
            'scanInfo': {
                'scanDate': datetime.now().strftime('%Y-%m-%d'),
                'engineVersion': 'Error',
                'duration': '0 seconds'
            }
        }