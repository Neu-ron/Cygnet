from scapy.all import sniff, Packet
import time
from cygnet_modules.netflow import *
from cygnet_modules import immune
from multiprocessing import Process, Pipe, Queue
import threading

class NetworkCollector:
    def __init__(
            self, 
            bpf_filter: str,
            network_flows: dict,
            stdout=None
        ):
        self._bpf_filter = bpf_filter
        self._network_flows = network_flows
        self._stdout = stdout

    def start(self):
        sniff(count=0,filter=self._bpf_filter,prn=self.process_packet, store=False)
        
    def process_packet(self, pkt: Packet):
            def pkt_proc(pkt: Packet):
                if pkt.haslayer('IP'):
                    #(limiting to TCP or UDP based packets only)
                    if pkt.haslayer('UDP') or pkt.haslayer('TCP'):
                        self._total_packets += 1
                        candidate1 = Pktops.get_key_from_packet(pkt) #first flow id candidate
                        #the bases of each side in the 2-sided bidrectional (!) flow
                        #e.g. for {192.10.67.8:90-8.8.8.8:443}, the bases are the substrings seperated by '-'
                        key_bases = candidate1.split('-')
                        candidate2 = f"{key_bases[1]}-{key_bases[0]}" #inverse of candidate1
                        #Checking if flow exists for the packet
                        if candidate1 in self._network_flows:
                            flow_id = candidate1
                        elif candidate2 in self._network_flows:
                            flow_id = candidate2
                        else:
                            flow_id = None
                        if flow_id != None:
                            #Updating flow
                            flow = self._network_flows[flow_id]
                            #if current source = netflow source
                            flow.update(pkt)
                            if self._stdout!=None:
                                self._stdout.put((flow.get_key(), flow.vectorise()))
                        else:
                            #if flow doesnt exist for the packet -> create new flow
                            flow = Netflow.netflow_from_packet(pkt)
                            self._network_flows[flow.get_key()] = flow
                return
            return pkt_proc(pkt)