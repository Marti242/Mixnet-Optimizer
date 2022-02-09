class EventLog:
    """EVENT_LOG"""

    def __init__(self, challenge_time: float):
        self.postprocess = {}
        self.send_packet = {}
        self.decoy_wrapper = {}
        self.process_packet = {}
        self.challenge_worker = [challenge_time, challenge_time]
        self.payload_to_sphinx = {}
        self.put_on_payload_queue = {}
