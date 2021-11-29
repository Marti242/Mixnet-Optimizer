from time                   import time
from queue                  import Queue
from socket                 import socket
from socket                 import AF_INET
from socket                 import SOCK_STREAM
from logging                import info
from selectors              import EVENT_READ
from selectors              import DefaultSelector
from sphinxmix.SphinxNode   import sphinx_process
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import PFdecode
from sphinxmix.SphinxClient import Dest_flag
from sphinxmix.SphinxClient import Relay_flag
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import unpack_message
from sphinxmix.SphinxClient import receive_forward

ID_TO_TYPE = {0: 'LEGIT', 1: 'LOOP', 2: 'DROP', 3: 'LOOP_MIX'}

class Node:
    
    def __init__(self, 
                 layer      : int, 
                 nodeId     : str, 
                 params     : SphinxParams,
                 cmdQueue   : Queue,
                 addBuffer  : int,
                 eventQueue : Queue):
        self.__port       = 49152 + int(nodeId[1:])
        self.__layer      = layer
        self.__params     = params
        self.__nodeId     = nodeId
        self.__selector   = DefaultSelector()
        self.__tagCache   = set()
        self.__cmdQueue   = cmdQueue
        self.__addBuffer  = addBuffer
        self.__eventQueue = eventQueue

        # Generate key pair.
        self.__secretKey  = params.group.gensecret()
        self.__publicKey  = params.group.expon(params.group.g, [ self.__secretKey ])
        self.__paramsDict = { (params.max_len, params.m) : params }
        
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
        
    def __acceptConnection(self, server : socket, mask):
        conn, _ = server.accept()

        conn.setblocking(False)
        self.__selector.register(conn, EVENT_READ, self.__processPacket)

    # Receives and processes Sphinx packet.
    def __processPacket(self, conn : socket, mask):
        data = conn.recv(self.__params.max_len + self.__params.m + self.__addBuffer)

        if data: 
            unpacked = unpack_message(self.__paramsDict, data)
            header   = unpacked[1][0]
            delta    = unpacked[1][1]

            processed = sphinx_process(self.__params, self.__secretKey, header, delta)
            tag       = processed[0]
            routing   = processed[1]

            routing = PFdecode(self.__params, routing)
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
                packed     = pack_message(self.__params, processed[2])
                queueTuple = (packed, nextNode, messageId, split, ofType, -1, self.__nodeId)

                self.__eventQueue.put((delay, queueTuple))

            elif flag == Dest_flag:
                delta  = processed[2][1]
                macKey = processed[3]

                dest, _ = receive_forward(self.__params, macKey, delta)

                destination = dest[0].decode('utf-8')
                msgId       = dest[1]
                split       = dest[2]
                ofType      = ID_TO_TYPE[dest[3]]
                timeStr     = "{:.7f}".format(time())

                # Log packet delivery.
                info('%s %s %s %s %s %s', timeStr, self.__nodeId, destination, msgId, split, ofType)

                # Inform the optimizer that a LEGIT packet is ready for the delivery to a user.
                if ofType == 'LEGIT':
                    self.__eventQueue.put((msgId, timeStr))
        else:

            # Close connection.
            self.__selector.unregister(conn)
            conn.close()

    # Run the server.
    def start(self,):

        # Serve multiple connections.
        while self.__cmdQueue.empty():
            events = self.__selector.select(timeout=7.879036505057893)
            
            for key, mask in events:
                callback = key.data
                
                callback(key.fileobj, mask)

        self.__selector.close()