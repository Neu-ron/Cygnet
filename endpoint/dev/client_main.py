from cygnet_modules import immune
from cygnet_modules.networkcapture import NetworkCollector
from cygnet_modules.client import Client
from cygnet_modules import utils as cyg
from multiprocessing import Process, Queue, freeze_support
import socket
import tensorflow as tf
import numpy as np
import sys
import os

CURDIR = os.path.dirname(os.path.abspath(__file__))
PAMP_MODEL_PATH = CURDIR+"/dev/assets/models/dae3_benign"
SAFE_MODEL_PATH = CURDIR+"/dev/assets/models/dae3_malicious"
SCALER_PATH = CURDIR+"/dev/assets/scaler.pkl"

#redirecting stdout and stderr to null to avoid output
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

def safe_extraction(data):
    """
    extracting safe signal value from reconstruction by autoencoder trained on malicious samples.
    the higher the RMSE value, the stronger indication input is benign
    """
    m = load_model(SAFE_MODEL_PATH) # m -> keras Model object (trained autoencoder)
    reconstructed = m(data)
    error_rate = cyg.rmse(data, reconstructed)
    return error_rate

def pamp_extraction(data):
    """
    extracting pamp signal value from reconstruction by autoencoder trained on benign samples.
    the higher the RMSE value, the stronger indication the input is malicious
    """
    m = load_model(PAMP_MODEL_PATH) # m -> keras Model object (trained autoencoder)
    reconstructed = m(data)
    error_rate = cyg.rmse(data, reconstructed)
    return error_rate

def load_model(model_path):
        return tf.keras.models.load_model(model_path)

def main(company_key):    
    #initialising the interprocess sharing queues
    dca_input_queue = Queue()
    dca_output = Queue()
    alert_queue = Queue()
    #starting communication with server (networking client)
    #initial connection and client-side process run
    #client's input queue = alert_queue
    hostname=socket.gethostname()
    addr=socket.gethostbyname(hostname)
    server_hostname = (company_key.split(':'))[1]
    server_addr = socket.gethostbyname(server_hostname)
    server_port = int((company_key.split(':'))[2])
    #alert_queue = Queue((alert_queue))
    client = Client(address=addr,
                    server_host=server_addr,
                    server_port=server_port,
                    name=hostname, 
                    company_hash=company_key,
                    alert_queue=alert_queue)  
    
    if not client.connect():
        sys.exit(cyg.EXIT_FAIL)
    
    #now starting the actual algorithmic detection components    
    sig_extractor = immune.SignalExtractor(
        [pamp_extraction, safe_extraction]
    )
    anomaly_threshold = 0.65
    #run lymph node before DCA starts
    lymph_node = immune.LymphNode(anomaly_threshold, dca_output, alert_queue)
    lymph_node_process = Process(group=None, target=lymph_node.start, name="LymphNode")
    lymph_node_process.start()
    #run DCA process with listening to to input_pipe
    dca = immune.DCA(
        dca_input_queue,
        dca_output,
        population_size=5,
        migration_range=(5,15),
        max_antigens=5,
        csm_weights=[2,2],
        k_weights=[2,-2],
        segment_size=20,
        signal_extractor=sig_extractor,
        in_signal=2,
    )
    dca_process = Process(group=None, target=dca.start, name="DCA")
    dca_process.start()

    #setting up netflow collection
    hostname=socket.gethostname()
    addr=socket.gethostbyname(hostname)
    network_flows = {}
    sniff_filter = f"ip and (tcp or udp) and (host {addr})" #sniffing only packets with layer 3, and only TCP or UDP
    collector = NetworkCollector(
        bpf_filter=sniff_filter, 
        network_flows=network_flows, 
        stdout=dca_input_queue
    )
    #starting sniffing process (data collection part of the system)
    sniffer_process = Process(group=None, target=collector.start, name="Sniffer")
    sniffer_process.start()
    
    terminator = cyg.Terminator()
    while not terminator.kill:
        #while the program is not terminated - sending alerts to server
        client.send_alert()
    #graceful termination/cleanup
    client.disconnect()
    dca_process.terminate()
    sniffer_process.terminate()
    dca_process.close()
    sniffer_process.close()
    return

if __name__=="__main__":
    if len(sys.argv) != 2:
        sys.exit(cyg.EXIT_FAIL)
    else:
        main(sys.argv[1])
        sys.exit(cyg.EXIT_SUCCESS)