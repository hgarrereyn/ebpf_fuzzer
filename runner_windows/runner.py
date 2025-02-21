from flask import Flask, request, jsonify
import subprocess
import tempfile
import os
import json
from pathlib import Path

app = Flask(__name__)

RUNNER = 'C:\\ebpf\\ebpf-for-windows\\x64\\Debug\\ebpf_conformance_runner.exe'
PLUGIN_PATH = 'C:\\ebpf\\ebpf-for-windows\\x64\\Debug\\bpf2c_plugin.exe'

def run_ebpf_conformance(prog_path, timeout_seconds=30):
    try:
        # Run the conformance runner with timeout
        result = subprocess.run(
            [
                RUNNER,
                '--test_file_path', prog_path,
                '--cpu_version', 'v4',
                '--exclude_regex', 'local',
                '--plugin_path', PLUGIN_PATH,
                '--debug', 'true',
                '--plugin_options', '\"--include C:/ebpf/ebpf-for-windows/include\"'
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds
        )
        
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "return_code": result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": f"Process timed out after {timeout_seconds} seconds"
        }
    except subprocess.SubprocessError as e:
        return {
            "success": False,
            "error": f"Failed to run conformance test: {str(e)}"
        }

@app.route('/run', methods=['POST'])
def run():
    print('Received request')
    try:
        # Get the JSON data from the request
        data = request.get_json()
        print(data)
        
        if not data or 'program' not in data:
            return jsonify({
                "status": "error",
                "message": "Request must include 'program' field"
            }), 400

        # Create a temporary directory for our files
        with tempfile.TemporaryDirectory() as temp_dir:
            prog_path = Path(temp_dir) / "test.prog"
            
            # Write the program to a file
            with open(prog_path, 'w') as f:
                f.write(data['program'])
            
            # Get timeout from request or use default
            timeout = data.get('timeout', 30)
            
            print('Running conformance test', data['program'])

            # Run the conformance test
            result = run_ebpf_conformance(prog_path, timeout)
            
            print('Conformance test result', result)

            # Prepare response
            response = {
                "status": "success" if result["success"] else "error",
                "result": result
            }
            
            return jsonify(response)
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Server error: {str(e)}"
        }), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 
