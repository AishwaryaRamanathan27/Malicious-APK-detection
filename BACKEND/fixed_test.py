# Try different import methods
print("Trying to import androguard...")

try:
    import androguard
    print(f"✅ androguard version: {androguard.__version__}")
    print(f"Available modules: {dir(androguard)}")
except Exception as e:
    print(f"❌ {e}")

print("\n" + "="*50)

try:
    from androguard.core.bytecodes import apk
    print("✅ Successfully imported from androguard.core.bytecodes.apk")
except Exception as e:
    print(f"❌ {e}")

print("\n" + "="*50)

try:
    from androguid.core.bytecodes import apk
    print("✅ Successfully imported from androguid.core.bytecodes.apk")
except Exception as e:
    print(f"❌ {e}")

print("\n" + "="*50)

try:
    import androguard.core
    print("✅ Imported androguard.core")
    print(dir(androguard.core))
except Exception as e:
    print(f"❌ {e}")