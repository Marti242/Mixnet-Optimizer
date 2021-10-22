from time                   import time
from time                   import sleep
from util                   import sendPacket
from util                   import generateMessage
from queue                  import PriorityQueue
from socket                 import socket
from socket                 import AF_INET
from socket                 import SOCK_STREAM
from logging                import info
from threading              import Thread
from selectors              import EVENT_READ
from selectors              import DefaultSelector
from constants              import LAMBDAS
from constants              import ID_TO_TYPE
from constants              import SPHINX_PARAMS
from numpy.random           import exponential
from sphinxmix.SphinxNode   import sphinx_process
from sphinxmix.SphinxClient import PFdecode
from sphinxmix.SphinxClient import Dest_flag
from sphinxmix.SphinxClient import Relay_flag
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import unpack_message
from sphinxmix.SphinxClient import receive_forward

class Node:
    
    # nodeId - 'm' for mix, 'p' for provider, followed by 6 digit ID string. providers are also 
    # identified by being on the 0th layer.
    def __init__(self, nodeId : str, layer : int):
        self.__port         = 49152 + int(nodeId[1:])
        self.__layer        = layer
        self.__nodeId       = nodeId
        self.__selector     = DefaultSelector()
        self.__tagCache     = set()

        # Generate key pair.
        self.__secretKey    = SPHINX_PARAMS.group.gensecret()
        self.__publicKey    = SPHINX_PARAMS.group.expon(SPHINX_PARAMS.group.g, [ self.__secretKey ])
        self.__paramsDict   = { (SPHINX_PARAMS.max_len, SPHINX_PARAMS.m) : SPHINX_PARAMS }
        self.__messageQueue = PriorityQueue()
        
        # Instantiate listener worker.
        server = socket(AF_INET, SOCK_STREAM)
        
        server.bind(('127.0.0.1', self.__port))
        server.listen()
        server.setblocking(False)
        self.__selector.register(server, EVENT_READ, self.__acceptConnection)

    # Export minimal node PKI info in a dict.
    def toPKIView(self,) -> dict:
        node              = dict()
        node['port'     ] = self.__port
        node['layer'    ] = self.__layer
        node['nodeId'   ] = self.__nodeId
        node['publicKey'] = self.__publicKey.export().hex()

        return node

    def setPKI(self, pki : dict):
        self.__pki = pki
        
    def __acceptConnection(self, server : socket, mask):
        conn, _ = server.accept()

        conn.setblocking(False)
        self.__selector.register(conn, EVENT_READ, self.__processPacket)

    # Receives and processes Sphinx packet.
    def __processPacket(self, conn : socket, mask):
        
        # 37 holds for body_len = 2 ** x for 8 <= x < 16.
        data = conn.recv(SPHINX_PARAMS.max_len + SPHINX_PARAMS.m + 37)

        if data:
            unpacked = unpack_message(self.__paramsDict, data)
            header   = unpacked[1][0]
            delta    = unpacked[1][1]

            processed = sphinx_process(SPHINX_PARAMS, self.__secretKey, header, delta)
            tag       = processed[0]
            routing   = processed[1]

            routing = PFdecode(SPHINX_PARAMS, routing)
            flag    = routing[0]

            # Check for tagging and replay attacks. Prevent repeating packets by keeping their tags
            # in a cache.
            if tag in self.__tagCache:
                print('REPLAY ATTACK')
                return
            else:
                self.__tagCache.add(tag)

            if flag == Relay_flag:
                nextNode  = routing[1][0]
                delay     = routing[1][1]
                messageId = routing[1][2]
                split     = routing[1][3]
                ofType    = ID_TO_TYPE[routing[1][4]]

                # Prepare message for the relay, put it on sender's queue, and inform it about 
                # sending time. Add logging info in the queueTuple to monitor traffic (routing info 
                # contains ground truth).
                packed      = pack_message(SPHINX_PARAMS, processed[2])
                queueTuple  = (packed, nextNode, messageId, split, ofType)
                sendingTime = time() + delay

                self.__messageQueue.put((sendingTime, queueTuple))

            elif flag == Dest_flag:
                delta  = processed[2][1]
                macKey = processed[3]

                dest, _ = receive_forward(SPHINX_PARAMS, macKey, delta)

                destination = dest[0].decode('utf-8')
                msgId       = dest[1]
                split       = dest[2]
                ofType      = ID_TO_TYPE[dest[3]]
                timeStr     = "{:.7f}".format(time())

                # Log packet delivery.
                info('%s %s %s %s %s %s', timeStr, self.__nodeId, destination, msgId, split, ofType)
        else:

            # Close connection.
            self.__selector.unregister(conn)
            conn.close()  

    # Worker that probes the message queue periodically emits decoy traffic and sends packets.
    def __sender(self,):

        # Instantiate state.
        data        = None
        sendingTime = time() + exponential(LAMBDAS['LOOP_MIX'])

        while True:

            # Check if there is any message to send and its delay has passed.
            if not self.__messageQueue.empty() and self.__messageQueue.queue[0][0] < time():
                data = self.__messageQueue.get()[1]

            # Node that is a mix generates LOOP_MIX decoy traffic periodically.
            elif self.__layer != 0 and sendingTime < time():
                data = generateMessage(self.__pki, self.__nodeId, 'LOOP_MIX')[0]

            if data is not None:

                # Unpack the data for sending.
                packet      = data[0]
                nextNode    = data[1]
                msgId       = data[2]
                split       = data[3]
                ofType      = data[4]
                nextAddress = self.__pki[nextNode]['port']

                sendPacket(packet, nextAddress)

                # Logging.
                timeStr = "{:.7f}".format(time())

                info('%s %s %s %s %s %s', timeStr, self.__nodeId, nextNode, msgId, split, ofType)
                
                # Reset state.
                data = None

                # Sample the sending time of next LOOP_MIX decoy message.
                if ofType == 'LOOP_MIX':
                    sendingTime = time() + exponential(LAMBDAS['LOOP_MIX'])
            else:
                sleep(0.01)

    # Run the server.
    def start(self,):

        # Instantiate worker that probes the message queue periodically, emits decoy traffic and 
        # sends packets.
        nodeSender = Thread(target=self.__sender)

        nodeSender.start()
        
        # Serve multiple connections.
        while True:
            events = self.__selector.select()
            
            for key, mask in events:
                callback = key.data
                
                callback(key.fileobj, mask)