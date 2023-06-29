import numpy as np
import random
from multiprocessing import Process, Queue

class SignalExtractor:
    def __init__(self, funcs):
        self._funcs = funcs

    def extract(self, data):
        signals = np.zeros(shape=len(self._funcs))
        i=0
        for f in self._funcs:
            signals[i]=f(data)
            i+=1
        return signals

class Antigen:
    def __init__(self, 
            antigen_id
        ):
        self._id = antigen_id

    def get_id(self):
        return self._id
            
    def __eq__(self, other):
        if self._id == other.get_id():
            return True
        return False
        
class AntigenProfile(Antigen):
    def __init__(self, antigen_id):
        super().__init__(antigen_id)
        self._mature_presentation = 0
        self._total_presentaion = 0

    @staticmethod
    def init_from_antigen(antigen: Antigen):
        return AntigenProfile(antigen_id=antigen.get_id())
    
    def presented(self, context):
        if context==1:
            self._mature_presentation+=1
        self._total_presentaion+=1
    
    def mcav(self):
        return self._mature_presentation/(self._total_presentaion+1)
    
class DCOutput:
    def __init__(self,
            k, 
            csm,
            antigens
    ):
        self.k = k
        self.csm = csm
        self.antigens = antigens
    
class DC:
    """
    represents a Dendritic Cell (DC) of the immune system
    
    Attributes:
    antigen_store (list): list of sampled antigens
    max_antigens (int): max antigens to sample
    migration_threshokd (float): migration threshold; if csm>migration_threshold, migration occurs
    signals (ndarray): signal matrix - 
        row 1 - pamp signal: [x1, x2, ..., Xn],\n
        row 2 - safe signal: [x1, x2, ..., Xn],\n
        row 3 - damp signal: [x1, x2, ..., Xn]
    weights (ndarray) weights to apply on signals for output signals
    output signals (ndarray):
            row 0: csm => costimulation level (accumulated in RT until csm > lifespan)
            row 1: k => context value (accumulated in RT)
    """
    def __init__(self, 
            migration_threshold, 
            max_antigens, 
            csm_weights, 
            k_weights, 
            in_signal=2, 
        ):
            self._migration_threshold = migration_threshold
            self._max_antigens = max_antigens
            self._ag_count = 0
            self._antigen_store = []
            self._weights = np.array([csm_weights[0:in_signal], k_weights[0:in_signal]])
            self._in_signal = in_signal
            self._signals = np.zeros(shape=in_signal, dtype=np.float64)
            self._output_signals = np.zeros(shape=2, dtype=np.float64)
            
    def phagocytose(self, antigen):
        if self._ag_count < self._max_antigens:
            self._antigen_store.append(antigen)
            return True
        return False

    def signal_update(self, signal_vector: np.ndarray):
        self._signals = self._signals+signal_vector
        self.update_output_signals()

    def update_output_signals(self):
        self._output_signals = self._weights.dot(self._signals)
    
    def set_signals(self, signal_vector):
        self._signals = signal_vector

    def set_output_signals(self, signal_vector):
        self._output_signals = signal_vector
    
    def csm(self):
        return self._output_signals[0]
    
    def k(self):
        return self._output_signals[1]
    
    def should_migrate(self)->bool:
        return self.csm()>=self._migration_threshold
    
    def present(self):
        return DCOutput(self.k, self.csm, self._antigen_store)
    
    def reset(self):
        self._signals = np.zeros(shape=self._in_signal, dtype=np.float64)
        self._output_signals = np.zeros(shape=2, dtype=np.float64)

class LymphNode():
    def __init__(self, anomaly_threshold, input_queue, alert_queue):
        self._anomaly_threshold = anomaly_threshold
        self._input_queue = input_queue
        self._alert_queue = alert_queue
        self._antigen_profiles = {}

    def update_antigen_profile(self, ag: Antigen, context):
        ag_id = ag.get_id()
        if ag_id not in self._antigen_profiles:
            self._antigen_profiles[ag_id] = AntigenProfile.init_from_antigen(ag)
        self._antigen_profiles[ag_id].presented(context)

    def detect_anomaly(self, ag_profile: AntigenProfile)->bool:
        if ag_profile.mcav()>self._anomaly_threshold:
            return True
        return False
    
    def anomaly_found(self, ag):
        self._alert_queue.put(ag.get_id())

    def get_migration(self, output: DCOutput):
        if output.k>1:
            context = 1
        else:
            context = 0
        for ag in output.antigens:
            self.update_antigen_profile(ag, context)
            is_anomaly = self.detect_anomaly(self._antigen_profiles[ag.get_id()])
            if is_anomaly:
                self.anomaly_found(ag)

    def start(self):
        while True:
            if not self._input_queue.empty():
                presentation = self._input_queue.get()
                if presentation==None:
                    break
                self.get_migration(presentation)

class DCA:
    def __init__(self,
            input_queue,
            output_queue,
            population_size, 
            migration_range, 
            max_antigens,
            csm_weights, 
            k_weights,
            segment_size,
            signal_extractor,
            in_signal=2, 
        ):
        self._input_queue = input_queue
        self._output_queue = output_queue
        self._population_size = population_size
        self._migration_range = migration_range
        self._max_antigens = max_antigens
        self._csm_weights = csm_weights
        self._k_weights = k_weights
        self._segment_size = segment_size
        self._signal_extractor = signal_extractor
        self._in_signal = in_signal
        self._population = []
        self._antigen_count = 0
        
    def initialise_population(self):
        for _ in range(self._population_size):
            mt = random.uniform(self._migration_range[0], self._migration_range[1])
            cell = DC(
                migration_threshold=mt,
                max_antigens=self._max_antigens,
                csm_weights=self._csm_weights,
                k_weights=self._k_weights,
                in_signal=self._in_signal,
            )
            self._population.append(cell)

    def migrate(self, dc: DC):
        #send dc's k value to the LymphNode
        self._output_queue.put(dc.present())

    def signal_update_all(self, signals):
        for cell in self._population:
            cell.signal_update(signals)
            if cell.should_migrate():
                self.migrate(cell)
                cell.reset()

    def signal_update(self, cell, signals):
        cell.signal_update(signals)
        if cell.should_migrate():
            self.migrate(cell)
            cell.reset()

    def sample_antigen(self, antigen: Antigen):
        if self._antigen_count<self._segment_size:
            index = self._antigen_count % self._population_size
            accept_ag = self._population[index].phagocytose(antigen)
            while accept_ag == False:
                index = (index+1) % self._population_size
                accept_ag = self._population[index].phagocytose(antigen)
            return index
        return None
                
    def population_context_reset(self):
        for cell in self._population:
            cell.reset()

    def start(self, iteration_limit=0):
        self.initialise_population()
        i = 0
        while True:
            while self._antigen_count<self._segment_size:
                data = self._input_queue.get()
                if data is None:
                    break
                #getting antigen and signals (ag-specific)
                ag, signals = Antigen(data[0]), self._signal_extractor.extract(data[1])
                j = self.sample_antigen(ag) #index of DC sampling the Ag 
                self._antigen_count += 1
                self.signal_update(self._population[j], signals)
            self.population_context_reset()
            i+=1
            if iteration_limit>0:
                if i>=iteration_limit:
                    break