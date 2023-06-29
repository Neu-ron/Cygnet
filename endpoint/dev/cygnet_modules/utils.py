import signal
import subprocess
import numpy as np
import pickle

#exit codes
EXIT_SUCCESS = 0 
EXIT_FAIL = 1

#connection status codes
AUTH_SUCCESS = "CONN"
AUTH_FAILURE = "FAIL"

#bytes for socket.recv to recieve 
RECV_SIZE = 1024

#Process handling
class Terminator:
    """
    object to handle/intercept termination signals (e.g. sigterm) a process gets 
    to enable graceful termination
    """
    kill = False
    def __init__(self):
        #binding to specific signals used for termination of a process
        signal.signal(signal.SIGINT, self.termination_handler)
        signal.signal(signal.SIGBREAK, self.termination_handler)
        signal.signal(signal.SIGTERM, self.termination_handler)

    def termination_handler(self, signum, frame):
        #upon getting a signal - the kill flag is set
        self.kill = True

def terminate_external_process(proc: subprocess.Popen):
    """
    Args:
        proc (subprocess.Popen): process to terminate

    Returns:
        bool: True if process terminated successfully, else False
    """
    if not proc.poll():
        try:
            proc.send_signal(signal.CTRL_BREAK_EVENT)
            proc.wait()
            return True
        except:
            if not proc.poll():
                return True
            return False
    return False

#DataOps
def rmse(y_true, y_pred):
    return np.sqrt(np.mean(np.square(y_true-y_pred)))

def get_numericals_categoricals(data):
    numericals = np.zeros((len(data),6), dtype=np.float64)
    categoricals = np.zeros((len(data),2), dtype=np.float64)
    for i in range(len(data)):
        numericals[i]=data[i][0:6]
        categoricals[i]=data[i][6:]
    return numericals, categoricals

def scale_test_data(data, scaler_path):
    #scaling data using the trained scaler
    numericals, categoricals = get_numericals_categoricals(data)
    with open(scaler_path, 'rb') as f:
        scaler = pickle.load(f)
    scaled_numericals = scaler.transform(numericals)
    return np.concatenate([scaled_numericals, categoricals], axis=1)