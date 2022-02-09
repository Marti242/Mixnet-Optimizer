from socket import socket
from socket import AF_INET
from socket import SOCK_DGRAM
from typing import Tuple

from numpy import log2
from numpy import array
from model.packet import Packet
from sphinxmix.SphinxNode import sphinx_process
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import PFdecode
from sphinxmix.SphinxClient import Dest_flag
from sphinxmix.SphinxClient import Relay_flag
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import unpack_message
from sphinxmix.SphinxClient import receive_forward

ID_TO_TYPE = {0: 'PAYLOAD', 1: 'LOOP', 2: 'DROP', 3: 'LOOP_MIX'}


class Node:
    """NODE"""

    def __init__(self,
                 layer: int,
                 node_id: str,
                 params: SphinxParams,
                 base_port: int,
                 add_buffer: int):
        self.__node_id = node_id
        self.__tag_cache = set()
        self.__add_buffer = add_buffer

        self.port = base_port + int(node_id[1:])
        self.layer = layer
        self.params = params
        self.secret_key = params.group.gensecret()
        self.public_key = params.group.expon(params.group.g, [self.secret_key])
        self.params_dict = {(params.max_len, params.m): params}

        self.k_t = 0
        self.l_t = 0
        self.h_t = 0.0

        self.n = 0
        self.prob_sum = array([0.0, 0.0, 0.0])

        self.sending_time = dict()
        self.last_latency = 0.0
        self.running_latency = 0.0

    def process_packet(self, data: bytes) -> Tuple:
        unpacked = unpack_message(self.params_dict, data)
        header = unpacked[1][0]
        delta = unpacked[1][1]

        processed = sphinx_process(self.params, self.secret_key, header, delta)
        tag = processed[0]
        routing = processed[1]

        routing = PFdecode(self.params, routing)
        flag = routing[0]

        if tag in self.__tag_cache:
            print('REPLAY ATTACK')
            raise Exception()

        self.__tag_cache.add(tag)

        if flag == Relay_flag:
            next_node = routing[1][0]
            delay = float(routing[1][1])
            of_type = ID_TO_TYPE[routing[1][2]]

            packed = pack_message(self.params, processed[2])
            queue_tuple = Packet(packed, next_node, of_type, self.__node_id)

            return delay, queue_tuple

        if flag == Dest_flag:
            delta = processed[2][1]
            mac_key = processed[3]

            dest, _ = receive_forward(self.params, mac_key, delta)
            msg_id = dest[1]
            of_type = ID_TO_TYPE[dest[3]]

            return msg_id, of_type

    def postprocess(self, timestamp: float, msg_id: str):
        latency = max([timestamp - send_time for send_time, _ in self.sending_time.values()])
        expected_delay = self.sending_time[msg_id][1]
        self.last_latency = timestamp - self.sending_time[msg_id][0]
        self.running_latency = 0.1 * latency + 0.9 * self.running_latency

        assert self.last_latency >= expected_delay, 'MESSAGE RECEIVED TOO EARLY'

        del self.sending_time[msg_id]

    def update_entropy(self,) -> float:
        denominator = (self.k_t + self.l_t)
        self.h_t = self.l_t * self.h_t / denominator

        if self.k_t != 0:
            self.h_t += self.k_t * log2(self.k_t) / denominator
            self.h_t -= self.k_t / denominator * log2(self.k_t / denominator)

        if self.l_t != 0:
            self.h_t -= self.l_t / denominator * log2(self.l_t / denominator)

        self.l_t = self.l_t + self.k_t - 1
        self.k_t = 0

        return self.h_t

    def listener(self,):
        with socket(family=AF_INET, type=SOCK_DGRAM) as server:
            server.bind(('127.0.0.1', self.port))

            data = None
            buffer_size = self.params.max_len + self.params.m + self.__add_buffer

            while data != b'TERMINATE_SIMULATION':
                data, _ = server.recvfrom(buffer_size)
