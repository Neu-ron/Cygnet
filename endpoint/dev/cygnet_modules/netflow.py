from scapy.all import Packet
import numpy as np
import json
import pickle
import sys
import os

CURDIR = os.path.dirname(os.path.abspath(__file__))
SCALER_PATH = CURDIR+"../assets/scaler.pkl"

class Pktops:
    @staticmethod
    def valid_packet(pkt):
        """returns whether the packet is a valid IP packet with TCP or UDP"""
        if pkt.haslayer('IP'):
            #udp=17, tcp=6
            if pkt['IP'].proto==17 or pkt['IP'].proto==6:
                return True
        return False

    @staticmethod
    def packet_validator(pkt):
        """validates the packet. if the packet is invalid - raises exception"""
        if not Pktops.valid_packet(pkt):
            raise Exception('INVALID PACKET')
    
    @staticmethod 
    def get_proto(pkt):
        """gets the protocol of the packet - UDP or TCP"""
        Pktops.packet_validator(pkt)
        proto = 'UDP' if pkt['IP'].proto==17 else 'TCP'
        return proto
 
    @staticmethod
    def get_key(sip, dip, sport, dport):
        key = f"{sip}:{sport}-{dip}:{dport}"
        return key
    
    @staticmethod
    def get_key_from_packet(pkt: Packet):
        proto = Pktops.get_proto(pkt)
        return Pktops.get_key(pkt['IP'].src, pkt['IP'].dst, pkt[proto].sport,
                            pkt[proto].dport)

class Netflow:
    """
    Network flow (2-sided communication stream metadata) object.
    
    Attributes:
        sip(str): source ip
        dip(string): destination ip
        sport(int): source port
        dport(int): destination port
        key(str): unique id key, in the format "{sip}:{dport}-{dip}:{dport}"
        proto(str): transaction protocol
        spkts(int): number of source->destination packets
        dpkts(int): number of destination->source packets
        sbytes(int): number of source->destination payload bytes
        dbytes(int): number of destination->source payload bytes
        spkts_size(int): number of source->destination total packet bytes
        dpkts_size(int): number of destination->source total packet bytes
        smean(float): mean source->destination packet size
        dmean(float): mean destination->source packet size
    """
    def __init__(self, 
            sip, 
            dip, 
            sport, 
            dport, 
            stime, 
            proto, 
            ibytes, 
            packet_size,
            key=None
        ):
        self._sip = sip
        self._dip = dip
        self._sport = sport
        self._dport = dport
        if key==None:
            self._key = Pktops.get_key(self._sip, self._dip, self._sport, self._dport)
        else:
            self._key = key
        self._proto = proto
        self._spkts = 1
        self._dpkts = 0
        self._sbytes = ibytes
        self._dbytes = 0
        self._spkts_size = packet_size
        self._dpkts_size = 0
        self._smean = packet_size
        self._dmean = 0
        
    @staticmethod
    def netflow_from_packet(pkt):
        proto = Pktops.get_proto(pkt)
        return Netflow(
                pkt['IP'].src, 
                pkt['IP'].dst, 
                pkt[proto].sport, 
                pkt[proto].dport,
                proto,
                len(pkt.payload),
                len(pkt),
            )
    def get_key(self):
        return self._key
    
    def update(self, pkt: Packet):
        """update the netflow with a new packet"""
        Pktops.packet_validator(pkt)
        side = 'src' if pkt['IP'].src == self._sip else 'dst'
        if side == 'src':
            self._spkts += 1
            self._spkts_size += len(pkt)
            self._smean = self._spkts_size/self._spkts
            self._sbytes += len(pkt.payload)
        elif side == 'dst':
            self._dpkts += 1
            self._dpkts_size += len(pkt)
            self._dmean = self._dpkts_size/self._dpkts
            self._dbytes += len(pkt.payload)
    
    @staticmethod
    def scale_vector(vector):
        #scaled according to training data scaler
        numericals, categoricals = vector[:,:6], vector[:, 6:]
        with open(SCALER_PATH, 'rb') as f:
            scaler = pickle.load(f)
        scaled_numericals = scaler.transform(numericals)
        return np.concatenate([scaled_numericals, categoricals], axis=1)
    
    def get_feature_vector(self):
        #defining the features
        is_tcp = 1 if self._proto == 'TCP' else 0
        is_udp = 1-is_tcp

        features = np.array(
            [self._spkts,
            self._dpkts,
            self._sbytes,
            self._dbytes,
            self._smean,
            self._dmean,
            is_tcp,
            is_udp]
        )
        return features.reshape(1,-1) #transposing the arr bc. it represents 1 sample
    
    def vectorise(self):
        #scaling the feature vector to match autoencoder training input
        return Netflow.scale_vector(self.get_feature_vector())
    
    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4)