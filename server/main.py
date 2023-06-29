import uuid
import socket
import json
import os
import subprocess
from dev.cygnet_modules import utils as cyg
import sys
import time
import webbrowser

CURDIR = os.path.dirname((__file__))

DEFAULT_PORT = 8000
APP_URL = "http://localhost:5000"
CONF_FILE = CURDIR+"/dev/configuration/config.json"
APP_PATH = CURDIR+"/dev/flask_server_app.py"
SERVER_PATH = CURDIR+"/dev/alertserver.py"

def generate_company_key():
    """returns a unique company key using a combination of a random ID, hostname, and port"""
    random_id = uuid.uuid4().hex
    hostname = socket.gethostname()
    return f"{random_id}:{hostname}:{DEFAULT_PORT}"
    
def main():
    #getting local machine's info to use
    hostname = socket.gethostname()
    address = socket.gethostbyname(hostname)
    #setting up inital default options for the config file
    server_options = {
        "server":{
            "name": hostname,
            "address": address,
            "port": DEFAULT_PORT
        },
        "company_hash": generate_company_key(),
        "admins":[]
    } #always listening on DEFAULT_PORT

    if not os.path.isfile(CONF_FILE):
        with open(CONF_FILE, 'w') as f:
            json.dump(server_options, f, indent=4)

    #starting server and flask app
    server_proc = subprocess.Popen(['python', SERVER_PATH])
    flask_proc =  subprocess.Popen(['python', APP_PATH])
    time.sleep(2)
    #on first execution, opening the web window for registration
    webbrowser.open(APP_URL, new=1) 
    #waiting for termination signal
    t = cyg.Terminator()
    while not t.kill:
        pass
    #graceful termination of external processes
    cyg.terminate_external_process(flask_proc)
    cyg.terminate_external_process(server_proc)
    return

if __name__=="__main__":
    main()
    sys.exit(cyg.EXIT_SUCCESS)