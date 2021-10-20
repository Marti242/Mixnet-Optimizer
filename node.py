from time                   import time
from time                   import sleep
from util                   import sendPacket
from util                   import msgWrapper
from util                   import ID_TO_TYPE
from util                   import LOOP_MIX_LAMB
from queue                  import PriorityQueue
from socket                 import socket
from socket                 import AF_INET
from socket                 import SOCK_STREAM
from selectors              import DefaultSelector
from selectors              import EVENT_READ
from threading              import Thread
from numpy.random           import exponential
from sphinxmix.SphinxNode   import sphinx_process
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import PFdecode
from sphinxmix.SphinxClient import Dest_flag
from sphinxmix.SphinxClient import Relay_flag
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import unpack_message
from sphinxmix.SphinxClient import receive_forward

class Node:
    
    def __init__(self, nodeId : str, layer : int):
        self.port         = 49152 + int(nodeId[1:])
        self.layer        = layer
        self.params       = SphinxParams(header_len=223)
        self.nodeId       = nodeId
        self.selector     = DefaultSelector()
        self.tagCache     = set()
        self.secretKey    = self.params.group.gensecret()
        self.publicKey    = self.params.group.expon(self.params.group.g, [ self.secretKey ])
        self.paramsDict   = { (self.params.max_len, self.params.m) : self.params }
        self.messageQueue = PriorityQueue()
        
        server = socket(AF_INET, SOCK_STREAM)
        
        server.bind(('127.0.0.1', self.port))
        server.listen()
        server.setblocking(False)
        self.selector.register(server, EVENT_READ, self.acceptConnection)

    def toPKIView(self,) -> dict:
        node              = dict()
        node['port'     ] = self.port
        node['layer'    ] = self.layer
        node['nodeId'   ] = self.nodeId
        node['publicKey'] = self.publicKey.export().hex()

        return node

    def setPKI(self, pki : dict):
        self.pki = pki
        
    def acceptConnection(self, server : socket, mask):
        conn, _ = server.accept()

        conn.setblocking(False)
        self.selector.register(conn, EVENT_READ, self.processPacket)

    def processPacket(self, conn : socket, mask):
        
        # 37 holds for body_len = 2 ** x for 8 <= x < 16.
        data = conn.recv(self.params.max_len + self.params.m + 37)

        if data:
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
                return
            else:
                self.tagCache.add(tag)

            if flag == Relay_flag:
                nextNode    = routing[1][0]
                delay       = routing[1][1]
                messageId   = routing[1][2]
                split       = str(routing[1][3])
                ofType      = ID_TO_TYPE[routing[1][4]]
                packed      = pack_message(self.params, processed[2])
                queueTuple  = (packed, nextNode, messageId, split, ofType)
                sendingTime = time() + delay

                self.messageQueue.put((sendingTime, queueTuple))

            elif flag == Dest_flag:
                delta  = processed[2][1]
                macKey = processed[3]

                dest, _ = receive_forward(self.params, macKey, delta)

                destination = dest[0].decode('utf-8')
                messageId   = dest[1]
                split       = str(dest[2])
                ofType      = ID_TO_TYPE[dest[3]]
                timeString  = "{:.7f}".format(time())

                logs = [timeString, self.nodeId, destination, messageId, split, ofType]

                print(' '.join(logs))
        else:
            self.selector.unregister(conn)
            conn.close()  

    def sender(self,):
        sendingTime = time() + exponential(LOOP_MIX_LAMB)

        while True:
            if not self.messageQueue.empty() and self.messageQueue.queue[0][0] < time():
                data        = self.messageQueue.get()
                packet      = data[1][0]
                nextNode    = data[1][1]
                messageId   = data[1][2]
                split       = data[1][3]
                ofType      = data[1][4]
                nextAddress = self.pki[nextNode]['port']

                sendPacket(packet, nextAddress)

                timeString = "{:.7f}".format(time())
                
                print(' '.join([timeString, self.nodeId, nextNode, messageId, split, ofType]))
            elif self.layer != 0 and sendingTime < time():
                loopMsg     = msgWrapper(self.pki, self.nodeId, 'LOOP_MIX')
                packet      = loopMsg[0][0]
                nextNode    = loopMsg[0][1]
                messageId   = loopMsg[0][2]
                nextAddress = self.pki[nextNode]['port']

                sendPacket(packet, nextAddress)

                timeString = "{:.7f}".format(time())
                
                print(' '.join([timeString, self.nodeId, nextNode, messageId, '0', 'LOOP_MIX']))

                sendingTime = time() + exponential(LOOP_MIX_LAMB)
            else:
                sleep(0.01)

    def start(self,):
        nodeSender = Thread(target=self.sender)

        nodeSender.start()
        
        while True:
            events = self.selector.select()
            
            for key, mask in events:
                callback = key.data
                
                callback(key.fileobj, mask)