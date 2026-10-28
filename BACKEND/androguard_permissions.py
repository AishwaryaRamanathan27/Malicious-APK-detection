from androguard.core.bytecodes import apk
import os

print("="*60)
print("ANDROGUARD PERMISSION TEST")
print("="*60)

# Find APK files
apk_files = [f for f in os.listdir('.') if f.endswith('.apk')]
print(f"Found {len(apk_files)} APK files")

for apk_file in apk_files:
    print(f"\n{'─'*60}")
    print(f"📱 Analyzing: {apk_file}")
    print('─'*60)
    
    try:
        # Load APK with androguard
        a = apk.APK(apk_file)
        
        # Get package info
        package = a.get_package()
        version = a.get_androidversion_name()
        print(f"📦 Package: {package}")
        print(f"📌 Version: {version}")
        
        # Get ALL permissions
        permissions = a.get_permissions()
        print(f"\n📋 TOTAL PERMISSIONS: {len(permissions)}")
        
        if permissions:
            # Show all permissions
            print("\n🔍 PERMISSIONS LIST:")
            for i, perm in enumerate(sorted(permissions), 1):
                print(f"  {i:2d}. {perm}")
            
            # Count by risk level
            high_risk = [p for p in permissions if any(x in p for x in ['READ_CONTACTS', 'SEND_SMS', 'CAMERA', 'RECORD_AUDIO', 'ACCESS_FINE_LOCATION'])]
            medium_risk = [p for p in permissions if any(x in p for x in ['ACCESS_COARSE_LOCATION', 'WRITE_EXTERNAL_STORAGE', 'GET_ACCOUNTS'])]
            
            print(f"\n⚠️  High Risk: {len(high_risk)}")
            print(f"🟡 Medium Risk: {len(medium_risk)}")
            print(f"🟢 Low Risk: {len(permissions) - len(high_risk) - len(medium_risk)}")
            
        else:
            print("❌ No permissions found!")
            
    except Exception as e:
        print(f"❌ Error analyzing {apk_file}: {e}")

print("\n" + "="*60)
print("TEST COMPLETE")
print("="*60)