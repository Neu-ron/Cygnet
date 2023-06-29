import socket
import sys
import threading
from multiprocessing import Queue
import json
import threading
from cygnet_modules import utils as cyg
from cygnet_modules.encryption import CygCrypt

class Client:    
    def __init__(self, address, server_host, server_port, name, 
                 company_hash, alert_queue):
        """
        :param address: _description_
        :param server_host: _description_
        :param server_port: _description_
        :param name: _description_
        :param company_hash: _description_
        :param alert_queue: _description_
        """        
        self._address = address
        if server_host == address:
            self._server_host = "127.0.0.1"
        else:
            self._server_host = server_host
        self._server_port = server_port
        self._socket = None
        self._name = name
        self._company_hash = company_hash
        self.alert_queue = alert_queue
        self._stop_flag = threading.Event()
        self.crypt = CygCrypt()

    def is_connected(self):
        return self._socket!=None
    
    def enc(self):
        self.crypt.generate_keys()
        public_key = self.crypt.serialised_public_key()
        self._socket.send(public_key)
        server_public_key = self._socket.recv(cyg.RECV_SIZE)
        self.crypt.shared_secret(server_public_key)

    def connect(self):
        try:
            if not self.is_connected():
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.connect((self._server_host, self._server_port))
                if self.authenticate():
                    self.enc()
                    return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        
    def disconnect(self):
        if self.is_connected():
            self._socket.close()
            self._socket = None
            return True
        else:
            return False
        
    def stop(self):
        self._stop_flag.set()
                
    def get_credentials(self):
        credentials = {
            'hostname': self._name,
            'company_hash': self._company_hash
        }
        return credentials
    
    def authenticate(self):
        credentials = self.get_credentials()
        data = json.dumps(credentials).encode()
        try:
            self._socket.send(data)
            response = self._socket.recv(cyg.RECV_SIZE).decode()
            if response!=cyg.AUTH_SUCCESS:
                self.disconnect() #disconnection & return if fail
                return False
            return True
        except:
            return False
        
    def send_alert(self):
        """
        _summary_
        """        
        if not self.alert_queue.empty():
            alert = self.alert_queue.get()
            if alert == None:
                return
            data = self.crypt.encrypt_msg(json.dumps(alert))
            self._socket.send(data)
        
    def send_alerts(self):
        while not self._stop_flag.is_set():
            self.send_alert()
        return
    
    def run(self):
        exec_thread = threading.Thread(target=self.send_alerts)
        exec_thread.start()
        exec_thread.join()
        self.disconnect()

    def test(self, example="10.0.0.1:1-10.0.0.5:443"):
        try:
            self._socket.send(self.crypt.encrypt_msg(f"TEST: {example}"))
            return True
        except Exception as e:
            raise e

def main(company_key, raw_alert_queue):
    #initial connection and client-side process run
    #client's input queue = alert_queue
    hostname=socket.gethostname()
    addr=socket.gethostbyname(hostname)
    server_hostname = (company_key.split(':'))[1]
    server_addr = socket.gethostbyname(server_hostname)
    server_port = int((company_key.split(':'))[2])
    alert_queue = Queue(int(raw_alert_queue))
    client = Client(address=addr,
                    server_host=server_addr,
                    server_port=server_port,
                    name=hostname, 
                    company_hash=company_key,
                    alert_queue=alert_queue)
    
    if not client.authenticate():
        return
    
    terminator = cyg.Terminator()
    while not terminator.kill:
        client.send_alert()
    client.disconnect()
    return

if __name__=="__main__":
    if len(sys.argv) != 3:
        pass
    else:
        main(sys.argv[1], sys.argv[2])
        sys.exit(0)