#!/usr/bin/env python3

import argparse
import requests
import sys
import os
import json

def send_file(http_path: str, filepath: str) -> None:
    """
    Send a file to the specified HTTP endpoint and print the response.
    
    Args:
        http_path (str): The full HTTP path to send the request to
        filepath (str): Path to the file to be sent
    """
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' does not exist")
        sys.exit(1)
        
    try:
        with open(filepath, 'r') as f:
            program_content = f.read()
            
        headers = {'Content-Type': 'application/json'}
        data = {'program': program_content}
        response = requests.post(http_path, headers=headers, json=data)
            
        print(f"Response status code: {response.status_code}")
        print("Response content:")
        print(response.text)
        
    except requests.exceptions.RequestException as e:
        print(f"Error sending request: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Send a file to a Flask server and print the response')
    parser.add_argument('http_path', help='The HTTP path to send the request to (e.g., http://localhost:5000/process)')
    parser.add_argument('filepath', help='Path to the file to send')
    
    args = parser.parse_args()
    send_file(args.http_path, args.filepath)

if __name__ == '__main__':
    main() 