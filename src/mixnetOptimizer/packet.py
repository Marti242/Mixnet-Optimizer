class Packet:
    """PACKET"""

    def __init__(self,
                 packet: bytes,
                 next_node: str,
                 msg_id: str,
                 split: str,
                 of_type: str,
                 expected_delay: float):
        self.packet = packet
        self.msg_id = msg_id
        self.next_node = next_node
        self.split = split
        self.of_type = of_type
        self.expected_delay = expected_delay
        self.sender = None
        self.num_splits = None
