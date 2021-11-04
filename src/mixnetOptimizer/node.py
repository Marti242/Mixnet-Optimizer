from time                   import time
from time                   import sleep
from util                   import sendPacket
from util                   import generateMessage
from numpy                  import log2
from queue                  import SimpleQueue
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
    
    # nodeId     - 'm' for mix, 'p' for provider, followed by 6 digit ID string. providers are also 
    #              identified by being on the 0th layer.
    # bodySize   - the size of plaintext in any mixnet packet in bytes.
    # cmdQueue   - queue synchronized with the optimizer. The optimizer uses it to propagate the 
    #              mixnet parameter updates across the network. It can also be used to send an empty 
    #              command that initiates the graceful termination of the mixnet.
    # addBuffer  - The excess of bytes that are needed to fully transfer a sphinx packet. Setting 
    #              the buffer size to bodySize + headerLen is not enough, about 40 additional bytes 
    #              are needed.
    # eventQueue - queue synchronized with optimizer. It is used to inform the optimizer when 
    #              a LEGIT message is received by the provider and ready for delivery to a user. The 
    #              optimizer compares the time when the message is received with the time when 
    #              it was sent to compute the E2E latency. Mixes, also inform the optimizer about 
    #              their entropy.
    def __init__(self, 
                 layer      : int, 
                 nodeId     : str, 
                 params     : SphinxParams, 
                 bodySize   : int, 
                 cmdQueue   : PriorityQueue,
                 addBuffer  : int,
                 eventQueue : SimpleQueue):

        # For entropy computation.
        self.__h = 0
        self.__k = 0
        self.__l = 0

        self.__port       = 49152 + int(nodeId[1:])
        self.__layer      = layer
        self.__params     = params
        self.__nodeId     = nodeId
        self.__lambdas    = LAMBDAS
        self.__lastCmd    = 0.
        self.__bodySize   = bodySize
        self.__cmdQueue   = cmdQueue
        self.__selector   = DefaultSelector()
        self.__tagCache   = set()
        self.__addBuffer  = addBuffer
        self.__eventQueue = eventQueue

        # Generate key pair.
        self.__secretKey    = params.group.gensecret()
        self.__publicKey    = params.group.expon(params.group.g, [ self.__secretKey ])
        self.__paramsDict   = { (params.max_len, params.m) : params }
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
                packed      = pack_message(self.__params, processed[2])
                queueTuple  = (packed, nextNode, messageId, split, ofType)
                sendingTime = time() + delay

                self.__messageQueue.put((sendingTime, queueTuple))

                self.__k += 1

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

    # Worker that probes the message queue periodically emits decoy traffic and sends packets.
    def __sender(self,):

        # Instantiate state.
        data          = None
        sendingTime   = time() + exponential(self.__lambdas['LOOP_MIX'])
        generatedLoop = False

        while True:

            # Check if there is any message to send and its delay has passed.
            if not self.__messageQueue.empty() and self.__messageQueue.queue[0][0] < time():
                data = self.__messageQueue.get()[1]

            # Node that is a mix generates LOOP_MIX decoy traffic periodically.
            elif self.__layer != 0 and sendingTime < time():
                data = generateMessage(self.__pki, 
                                       self.__nodeId, 
                                       'LOOP_MIX', 
                                       self.__params, 
                                       self.__bodySize, 
                                       self.__bodySize,
                                       self.__lambdas['DELAY'])[0]
                
                generatedLoop = True

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
                if generatedLoop:
                    sendingTime   = time() + exponential(self.__lambdas['LOOP_MIX'])
                    generatedLoop = False

                # On sending a message compute the entropy incrementally.
                elif self.__k != 0 or self.__l != 0:
                    denominator = (self.__k + self.__l)
                    h_t         = self.__l * self.__h / denominator

                    if self.__k != 0:
                        h_t += self.__k * log2(self.__k) / denominator
                        h_t -= self.__k / denominator * log2(self.__k / denominator)

                    if self.__l != 0:
                        h_t -= self.__l / denominator * log2(self.__l / denominator)

                    # Inform the optimizer about the current entropy level.
                    self.__eventQueue.put((self.__nodeId, float(h_t)))

                    self.__h = h_t
                    self.__l = len(self.__messageQueue.queue)
                    self.__k = 0

            # Empty command gracefully terminates the worker.
            if not self.__cmdQueue.empty():
                cmd = self.__cmdQueue.get()

                if len(cmd) == 0:
                    self.__cmdQueue.put([])
                    break

                # Update the mixnet parameters.
                elif self.__lastCmd < cmd[0]:
                    self.__lambdas = cmd[1][1]
                    self.__lastCmd = cmd[0]

                    cmd[1][0] -= 1
                    
                # When the counter reaches 0, all workers have successfully updated their 
                # parameters.
                if cmd[1][0] > 0:
                    self.__cmdQueue.put(cmd)
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
            events = self.__selector.select(timeout=LAMBDAS['DELAY'])
            
            for key, mask in events:
                callback = key.data
                
                callback(key.fileobj, mask)

            # Gracefully shut down the mix. sender worker propagates the close command.
            if not nodeSender.is_alive():
                self.__selector.close()
                break

        nodeSender.join()