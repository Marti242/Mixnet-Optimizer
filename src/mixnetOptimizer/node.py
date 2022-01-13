from time import time
from socket import socket
from socket import AF_INET
from socket import SOCK_DGRAM
from typing import Generator
from logging import info

from numpy import log2
from simpy import Environment
from sphinxmix.SphinxNode import sphinx_process
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import PFdecode
from sphinxmix.SphinxClient import Dest_flag
from sphinxmix.SphinxClient import Relay_flag
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import unpack_message
from sphinxmix.SphinxClient import receive_forward

ID_TO_TYPE = {0: 'LEGIT', 1: 'LOOP', 2: 'DROP', 3: 'LOOP_MIX'}


class Node:
    """NODE"""

    def __init__(self, layer: int, node_id: str, params: SphinxParams, add_buffer: int):
        self.__params = params
        self.__node_id = node_id
        self.__tag_cache = set()
        self.__add_buffer = add_buffer
        self.__secret_key = params.group.gensecret()
        self.__params_dict = {(params.max_len, params.m): params}

        self.port = 49152 + int(node_id[1:])
        self.layer = layer
        self.public_key = params.group.expon(params.group.g, [self.__secret_key])

        self.h_t = 0
        self.k_t = 0
        self.l_t = 0

    def process_packet(self, env: Environment, data: bytes) -> Generator:
        start_time = time()
        unpacked = unpack_message(self.__params_dict, data)
        header = unpacked[1][0]
        delta = unpacked[1][1]

        processed = sphinx_process(self.__params, self.__secret_key, header, delta)
        tag = processed[0]
        routing = processed[1]

        routing = PFdecode(self.__params, routing)
        flag = routing[0]

        if tag in self.__tag_cache:
            print('REPLAY ATTACK')
            yield env.timeout(time() - start_time)
            raise Exception()

        self.__tag_cache.add(tag)

        if flag == Relay_flag:
            next_node = routing[1][0]
            delay = routing[1][1]
            message_id = routing[1][2]
            split = routing[1][3]
            of_type = ID_TO_TYPE[routing[1][4]]

            packed = pack_message(self.__params, processed[2])
            queue_tuple = (packed, next_node, message_id, split, of_type, -1, self.__node_id)

            yield env.timeout(time() - start_time)
            return delay, queue_tuple

        if flag == Dest_flag:
            delta = processed[2][1]
            mac_key = processed[3]

            dest, _ = receive_forward(self.__params, mac_key, delta)

            destination = dest[0].decode('utf-8')
            msg_id = dest[1]
            split = dest[2]
            of_type = ID_TO_TYPE[dest[3]]

            yield env.timeout(time() - start_time)

            time_str = f"{env.now:.7f}"

            info('%s %s %s %s %s %s', time_str, self.__node_id, destination, msg_id, split, of_type)

            if of_type == 'LEGIT':
                return msg_id, time_str

        return None, None

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
            buffer_size = self.__params.max_len + self.__params.m + self.__add_buffer

            while data != b'TERMINATE_SIMULATION':
                data, _ = server.recvfrom(buffer_size)
