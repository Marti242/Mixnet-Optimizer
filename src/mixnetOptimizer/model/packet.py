from numpy import array
from typing import Optional


class Packet:
    """PACKET"""

    def __init__(self,
                 packet: bytes,
                 next_node: str,
                 msg_id: str,
                 split: str,
                 of_type: str,
                 sender: str,
                 expected_delay: Optional[float] = None,
                 num_splits: Optional[int] = None):
        self.packet = packet
        self.msg_id = msg_id
        self.next_node = next_node
        self.split = split
        self.of_type = of_type
        self.sender = sender
        self.expected_delay = expected_delay
        self.num_splits = num_splits

        if of_type != 'LOOP_MIX':
            self.dist = array([0.0, 0.0, 1.0])
