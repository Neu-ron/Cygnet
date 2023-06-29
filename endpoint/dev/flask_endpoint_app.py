from flask import Flask, render_template, request, redirect, url_for, jsonify
import subprocess
import re
from cygnet_modules import utils as cyg
import sys
import os
import multiprocessing

CURDIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_MAIN_PATH = CURDIR+"/client_main.py"

#redirecting stdout and stderr to null to avoid output
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

app = Flask(__name__)

class ClientProcess:
    def __init__(self):
        self.process = None

    def start(self, auth_key):
        if not self.is_running():
            try:
                self.process = subprocess.Popen(['python', CLIENT_MAIN_PATH, auth_key])
                return True
            except:
                return False
        return False

    def stop(self):
        if self.is_running():
            try:
                cyg.terminate_external_process(self.process)
            except:
                return False
            finally:
                return True

    def is_running(self):
        if self.process != None:
            return (self.process.poll() != None)
        return False

client_process = ClientProcess()

#validating key format
def validate_key_format(key):
    """
    evaluates the company key is in the correct format

    Args:
        key (str): company/authorisation key

    Returns:
        bool: true if format is valid, else false
    """
    
    #regular expressions for validation
    uuid_regex = r"^[0-9a-f]{32}$"
    hostname_regex = r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$"
    port_regex = r"^\d+$"
    #splitting the key into uuid, hostname, and port
    parts = key.split(':')
    if len(parts) != 3:
        return False
    uuid, hostname, port = parts
    return re.match(uuid_regex, uuid) and re.match(hostname_regex, hostname) and re.match(port_regex, port)

@app.route('/')
def home():
    return render_template('index.html')

#validating the company key
@app.route('/validate_key', methods=['POST'])
def validate_key():
    key = request.form.get('key')
    if validate_key_format(key):
        return jsonify({'valid': True})
    else:
        return jsonify({'valid': False, 'message': 'Invalid key format'})

#connecting to the server 
@app.route('/connect', methods=['GET', 'POST'])
def connect():
    """Attempts to connect to the server. Renders/redirects webpages along the way 
    to indicate success/failure"""
    if request.method == 'POST':
        if not client_process.is_running():
            company_key = request.form['key']
            if client_process.start(company_key):
                return redirect(url_for('connection_success'))
            else:
                err_message = "Authentication failed. Please check the authentication key."
                return redirect(url_for('error', message=err_message))
        else:
            err_message = "Already connected to Cygnet server."
            return redirect(url_for('error', message=err_message))
    else:
        return render_template('connect.html')

#disconnecting from the server
@app.route('/disconnect', methods=['POST'])
def disconnect():
    if client_process.is_running():
        if client_process.stop():
            return redirect(url_for('disconnection_success'))
        else:
            err_message = "Unable to terminate connection"
            return redirect(url_for('error', message=err_message))
    else:
        err_message = "Not connected to Cygnet server."
        return redirect(url_for('error', message=err_message))

#connection success page
@app.route('/connection_success')
def connection_success():
    return render_template('connection_success.html')

#disconnection success page
@app.route('/disconnection_success')
def disconnection_success():
    return render_template('disconnection_success.html')

#error page
@app.route('/error/<err>')
def error(err):
    #displays the error message in the rendered error page
    return render_template('error.html', message=err)

if __name__ == "__main__":
    multiprocessing.freeze_support()
    app.run(host="localhost", port=5001, debug=False)
    #maintaining the server until termination signal
    t = cyg.Terminator()
    while not t.kill:
        pass
    #graceful termination/cleanup
    client_process.stop()
    sys.exit(0)