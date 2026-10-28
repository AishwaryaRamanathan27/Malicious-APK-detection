import os
import zipfile
import re

print("="*60)
print("DETAILED APK TEST")
print("="*60)

current_dir = os.getcwd()
print(f"Current directory: {current_dir}")

# Find APK file
apk_files = [f for f in os.listdir('.') if f.endswith('.apk')]

if not apk_files:
    print("❌ No APK files found!")
    exit()

test_apk = apk_files[0]
print(f"\n✅ Testing APK: {test_apk}")

try:
    with zipfile.ZipFile(test_apk, 'r') as zip_ref:
        files = zip_ref.namelist()
        print(f"📁 Total files: {len(files)}")
        
        # Show all XML files
        xml_files = [f for f in files if f.endswith('.xml')]
        print(f"\n📋 XML files found ({len(xml_files)}):")
        for f in xml_files[:10]:
            print(f"  - {f}")
        
        # Find manifest
        manifest = None
        for f in files:
            if 'AndroidManifest.xml' in f:
                manifest = f
                break
        
        if manifest:
            print(f"\n✅ Reading manifest: {manifest}")
            data = zip_ref.read(manifest)
            
            # Try to decode and show first 500 chars
            try:
                text = data.decode('utf-8', errors='ignore')
                print("\n📝 MANIFEST PREVIEW (first 500 chars):")
                print("-"*40)
                print(text[:500])
                print("-"*40)
                
                # Look for permission patterns
                patterns = [
                    r'android\.permission\.[A-Z_]+',
                    r'<uses-permission',
                    r'permission',
                    r'android:name="([^"]+)"'
                ]
                
                for pattern in patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        print(f"\n🔍 Pattern '{pattern}' found {len(matches)} matches")
                        for m in matches[:5]:
                            print(f"  - {m}")
                
            except Exception as e:
                print(f"❌ Error decoding manifest: {e}")
        else:
            print("❌ No manifest found!")
            
except Exception as e:
    print(f"❌ Error: {e}")