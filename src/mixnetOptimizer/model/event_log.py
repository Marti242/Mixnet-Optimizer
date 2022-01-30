class EventLog:
    """EVENT_LOG"""

    def __init__(self):
        self.postprocess = {}
        self.send_packet = {}
        self.decoy_wrapper = {}
        self.process_packet = {}
        self.challenge_worker = [None, None]
        self.payload_to_sphinx = {}
        self.put_on_payload_queue = {}
