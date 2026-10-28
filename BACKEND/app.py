from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import tempfile
import shutil
from datetime import datetime
from apk_analyzer import analyze_apk_file

app = Flask(__name__)
# Allow all origins for development
CORS(app, origins=['http://127.0.0.1:5500', 'http://localhost:5500', 'http://127.0.0.1:5501', 'http://localhost:5501'])

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "APK Detection System API is running"})

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

@app.route('/analyze', methods=['POST'])
def analyze_apk():
    try:
        # Check if file was uploaded
        if 'apk' not in request.files:
            return jsonify({'error': 'No APK file provided'}), 400
        
        file = request.files['apk']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check if it's an APK file
        if not file.filename.endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Create temp directory
        temp_dir = tempfile.mkdtemp()
        temp_path = os.path.join(temp_dir, file.filename)
        file.save(temp_path)
        print(f"✅ File saved to: {temp_path}")
        
        # Get options
        detailed_scan = request.form.get('detailedScan', 'true') == 'true'
        compare_permissions = request.form.get('comparePermissions', 'true') == 'true'
        
        # Analyze the APK
        results = analyze_apk_file(
            temp_path, 
            detailed_scan=detailed_scan,
            compare_permissions=compare_permissions
        )
        
        # Add filename if not present
        if 'fileName' not in results:
            results['fileName'] = file.filename
        
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        print(f"✅ Analysis complete for: {file.filename}")
        
        return jsonify(results)
        
    except Exception as e:
        print(f"❌ Error in analyze_apk: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting APK Detection System Backend...")
    print("📡 Server will run on http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)