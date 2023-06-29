import json
import smtplib
from email.message import EmailMessage
import socket
import threading
import sys
import os
from cygnet_modules import alerts
from cygnet_modules import utils as cyg
from cygnet_modules.encryption import CygCrypt

CURDIR = os.path.dirname(os.path.abspath(__file__))

CONF_PATH = CURDIR+"/configuration/config.json"
APP_MAIL_JSON = CURDIR+"/configuration/app_mail.json"

#redirecting stdout and stderr to null, to avoid output
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

class Endpoint:
    def __init__(self, client_socket, address, name):
        self._client_socket = client_socket
        self._address = address
        self._name = name
    
    def get_name(self):
        return self._name
    
    def get_address(self):
        return self._address
    
    def close(self):
        """closes the socket connection to the endpoint"""
        self._client_socket.close()

class AlertServer:
    def __init__(self, host, port, config_file):
        self._host = host
        self._port = port
        self._endpoints = {}
        self._config_file = config_file
        self._server_socket = None
        self._threads = [] #list of active threads 
        self._email_address = None #email address of the server (updated when connecting to smtp)
    
    def smtp_login(self):
        """logging in to the SMTP server using the app email credentials"""
        with open(APP_MAIL_JSON, 'r') as f:
            app_mail = json.load(f)
        #getting credentials from config file
        key = app_mail['key']
        self._email_address = app_mail['address']
        #logging in
        self._smtp_server = smtplib.SMTP("smtp.gmail.com", port=587)
        self._smtp_server.starttls()
        self._smtp_server.login(self._email_address, key)

    def close_all(self):
        """closing all socket connections"""
        self._server_socket.close()
        for e in self._endpoints.values():
            e.close()        
        return
    
    def stop(self):
        #termination of the server
        self.close_all()
        self._smtp_server.quit()

    def start(self):
        self.smtp_login()
        #setting up the server
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind((self._host, self._port))
        self._server_socket.listen(5)
        t = cyg.Terminator()
        while not t.kill:
            #handling incoming connections
            client_socket, client_address = self._server_socket.accept()
            #each connection handled in separate thread
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket, client_address)
            )
            self._threads.append(client_thread)
            client_thread.start()
        #when termination signal is recieved - server is terminated
        self.stop()
        return

    def handle_client(self, client_socket, client_address):
        endpoint = None
        authenticated = False

        try:
            #recieves authentication key and processes it
            authentication = client_socket.recv(cyg.RECV_SIZE)
            credentials = json.loads(authentication.decode())
            authenticated = self.authenticate(credentials)
            if authenticated:
                endpoint = Endpoint(client_socket, 
                                    client_address[0],
                                    credentials['hostname'])
                self._endpoints[threading.current_thread()] = endpoint
                self.send_authentication_result(client_socket, True)
            else:
                self.send_authentication_result(client_socket, False)
                return
        except Exception:
            self.send_authentication_result(client_socket, False)
            return
        
        #sends email to inform admins a new endpoint connected to the system
        self.send_emails(self.get_admins(), msg=f"{endpoint.get_name()} on \
                          ({endpoint.get_address} connected to the system", 
                          subject="New endpoint connected")
        
        #setting up encryption with diffie-hellman exchange
        crypt = CygCrypt()
        crypt.generate_keys() 
        public_key = crypt.serialised_public_key()
        client_public_key = client_socket.recv(cyg.RECV_SIZE) #getting client public key
        crypt.shared_secret(client_public_key) #computing encryption key
        client_socket.send(public_key) #sending the client the server's public key

        while True:
            try:
                data = client_socket.recv(cyg.RECV_SIZE)
                if not data:
                    break
                decrypted = crypt.decrypt_msg(data)
                name = endpoint.get_name()
                alert = self.process_alert(endpoint.get_address(), name, 
                                            decrypted) #processing and formatting the alert from the endpoint
                self.send_alert(alert) #sending the alerts to the admins
            except:
                break

        #when socket is closed - deleting the endpoint object and closing connection
        del self._endpoints[threading.current_thread()]
        endpoint.close() 

    def get_config(self):
        """returns the server configuration options (from the config file)"""
        with open(self._config_file, 'r') as f:
            config = json.load(f)
        return config
    
    def save_config(self, config):
        """saves the input configuration options to the config file"""
        with open(self._config_file, 'w') as f:
            json.dump(config, f, indent=4)

    def get_company_hash(self):
        config = self.get_config()
        return config['company_hash']
    
    def get_admins(self):
        """returns the email addresses of the registered admins"""
        config = self.get_config()
        return config['admins']

    def authenticate(self, credentials: dict):
        """
        Authenticates the endpoint.
        
        Args: 
            credentials (dict): credentials sent by the endpoint for authentication

        Returns:
            bool: True if authentication is successful, else False
        """
        if 'company_hash' in credentials.keys():
            if credentials['company_hash'] == self.get_company_hash():
                return True
        return False
    
    def send_authentication_result(self, client_socket, success):
        result = cyg.AUTH_SUCCESS if success else cyg.AUTH_FAILURE
        data = result.encode()
        client_socket.send(data)

    def process_alert(self, endpoint_addr, endpoint_name, netflow):
        return alerts.Alert(endpoint_addr, endpoint_name, netflow)

    def send_email(self, destination_email, body, subject):
        """
        sends email to the specified address. 

        Args:
            destination_email (str): the destination email address
            body (str): message to send
            subject (str): subject of the email
        """
        msg = EmailMessage()
        msg.set_content(body)
        msg['to'] = destination_email
        msg['from'] = self._email_address
        msg['subject'] = subject
        self._smtp_server.send_message(msg)
    
    def send_emails(self, emails, msg: str, subject):
        for email in emails:
            self.send_email(email, msg, subject)

    def send_alert(self, alert: alerts.Alert, subject=None):
        admins = self.get_admins()
        if subject == None:
            subject = f"New threat detected on {alert.endpoint}"
        self.send_emails(admins, str(alert), subject)

if __name__=="__main__":
    server = AlertServer("localhost", 8000, CONF_PATH)
    server.start()