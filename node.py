import time
import socket

from util                   import sendPacket
from sphinxmix.SphinxNode   import sphinx_process
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import PFdecode
from sphinxmix.SphinxClient import Dest_flag
from sphinxmix.SphinxClient import Relay_flag
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import unpack_message
from sphinxmix.SphinxClient import receive_forward


class Node:
    
    def __init__(self, nodeId : str, layer : int, params : SphinxParams = SphinxParams()):
        self.port       = 49152 + int(nodeId[1:])
        self.layer      = layer
        self.params     = params
        self.nodeId     = nodeId
        self.tagCache   = set()
        self.secretKey  = self.params.group.gensecret()
        self.publicKey  = self.params.group.expon(self.params.group.g, [ self.secretKey ])
        self.paramsDict = { (self.params.max_len, self.params.m) : self.params }

    def toPKIView(self,):
        node              = dict()
        node['port'     ] = self.port
        node['layer'    ] = self.layer
        node['nodeId'   ] = self.nodeId
        node['publicKey'] = self.publicKey.export().hex()

        return node

    def setPKI(self, pki : dict):
        self.pki = pki

    def start(self,):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.bind(('127.0.0.1', self.port))
            server.listen()

            while True:
                conn, _ = server.accept()

                with conn:

                    # 37 holds for body_len = 2 ** x for 8 <= x < 16, rest sphinx params should 
                    # be as default.
                    data = conn.recv(self.params.max_len + self.params.m + 37)

                    # Defensive programming - control entry to kill the process
                    if data == b'SHUTDOWN':
                        server.close()
                        break

                    elif data:
                        unpacked = unpack_message(self.paramsDict, data)
                        header   = unpacked[1][0]
                        delta    = unpacked[1][1]

                        processed = sphinx_process(self.params, self.secretKey, header, delta)
                        tag       = processed[0]
                        info      = processed[1]

                        routing = PFdecode(self.params, info)
                        flag    = routing[0]

                        if tag in self.tagCache:
                            print('REPLAY ATTACK')
                            continue
                        else:
                            self.tagCache.add(tag)

                        if flag == Relay_flag:
                            prevNode    = routing[1][0]
                            nextNode    = routing[1][1]
                            packed      = pack_message(self.params, processed[2])
                            nextAddress = self.pki[nextNode]['port']
                            
                            sendPacket(packed, nextAddress)

                            # Log mix knowledge - packet sending time and immediate nodes on the 
                            # path - previous (can be user in case of provider), current, next.
                            path = ' -> '.join([prevNode, self.nodeId, nextNode])

                            print(str(time.time()) + ': ' + path)

                        elif flag == Dest_flag:
                            delta  = processed[2][1]
                            macKey = processed[3]

                            _, msg = receive_forward(self.params, macKey, delta)
                            print(msg)