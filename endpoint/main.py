import webbrowser
import subprocess
from dev.cygnet_modules import utils as cyg
import sys
import os
from multiprocessing import freeze_support

CURDIR = os.path.dirname(os.path.abspath(sys.argv[0]))

APP_PATH = CURDIR+"/dev/flask_endpoint_app.py"

def main():
    flask_proc = subprocess.Popen(['python', APP_PATH])
    t = cyg.Terminator()
    while not t.kill:
        pass
    cyg.terminate_external_process(flask_proc)
    return

if __name__ == "__main__":
    freeze_support()
    main()