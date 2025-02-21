from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/run', methods=['POST'])
def run():
    # Get the JSON data from the request
    data = request.get_json()
    
    # Print the contents of the received JSON
    print("Received JSON data:", data)
    
    # Return a response JSON
    response = {
        "status": "success",
        "message": "Request received and processed",
        "received_data": data
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 
