class Alert:
        def __init__(self, endpoint, endpoint_name, netflow_key):
            alert = {}
            self.endpoint = endpoint
            self.endpoint_name = endpoint_name
            temp = netflow_key.split('-')
            temp[0].split(':')
            temp[1].split(':')
            alert['sip']=temp[0][0]
            alert['sport']=temp[0][1]
            alert['dip']=temp[1][0]
            alert['dport']=temp[1][1]
            self._alert_msg = f"Threat detected on {self.endpoint_name} ({self.endpoint}) on your network.\n\
                Source:\nIP - {alert['sip']}, port - {alert['sport']}\n\
                Destination:\nIP - {alert['dip']}, port - {alert['dport']}"
        
        def get_alert(self):
            return self._alert_msg
        
        def __str__(self):
            return self._alert_msg