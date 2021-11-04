from time         import time
from time         import sleep
from util         import sendPacket
from queue        import Queue
from queue        import SimpleQueue
from queue        import PriorityQueue
from typing       import Callable
from logging      import info
from constants    import LAMBDAS
from constants    import LEGIT_LAG
from numpy.random import exponential

class Client:

    # userId       - 'u' followed by 6 digit ID string (over 100k users in the training set).
    # bodySize     - the size of plaintext in a mixnet packet in bytes.
    # rawMails     - a list of LEGIT email objects that the user should send at a particular time 
    #                in the simulation. A single email object is a dictionary, with:
    #                    - time - timestamp relative to the start of LEGIT traffic emission in the 
    #                      network indicates when the message should be sent in the simulation.
    #                    - sender - the ID of the sending user.
    #                    - size - integer, number of bytes in the email's plaintext.
    #                    - receiver - the ID of a single receiving user. The emails that had 
    #                      multiple receivers were split into emails of the same sizes, sending 
    #                      times and senders, but one receiver per email.
    # cmdQueue     - queue synchronized with the optimizer. The optimizer uses it to propagate the 
    #                mixnet parameter updates across the network. It can also be used to send 
    #                an empty command that initiates the graceful termination of the mixnet.
    # eventQueue   - queue synchronized with optimizer. It is used to inform the optimizer when 
    #                a LEGIT message is sent. This information is used for latency computation.
    # providerPort - Port at which user's provider listens for a connection.
    # msgGenerator - wrapper function for generation messages encapsulated in Sphinx packets 
    #                implicitly gives the client access to the PKI info.
    def __init__(self, 
                 userId       : str, 
                 bodySize     : int, 
                 rawMails     : list,
                 cmdQueue     : PriorityQueue,
                 eventQueue   : SimpleQueue,
                 providerPort : int,
                 msgGenerator : Callable):
        self.__userId       = userId
        self.__lastCmd      = 0.
        self.__lambdas      = LAMBDAS
        self.__bodySize     = bodySize
        self.__cmdQueue     = cmdQueue
        self.__rawMails     = PriorityQueue()
        self.__eventQueue   = eventQueue
        self.__msgGenerator = msgGenerator
        self.__messageQueue = Queue()
        self.__providerPort = providerPort

        # Schedule the LEGIT emails for sending. The LEGIT traffic should start once the mixnet 
        # is well established, so decoy traffic flows through it. Therefore, schedule LEGIT traffic
        # after some initial delay in LEGIT_LAG.
        for mail in rawMails:
            self.__rawMails.put_nowait((time() + mail['time'] + LEGIT_LAG, mail))

    # Simulate a client.
    def start(self,):

        # Initialize state. updateType informs what kind of packet was sent and which timer should 
        # be reset. legitSend indicates whether the client has sent a LEGIT packet.
        data       = None
        legitSend  = False
        updateType = None

        # Dictionary of times at which the next packet of a given type should be emitted. 
        timers = dict()

        # Sample the initial sending times for messages of a given type.
        timers['DROP' ] = time() + exponential(self.__lambdas['DROP'])
        timers['LOOP' ] = time() + exponential(self.__lambdas['LOOP'])
        timers['LEGIT'] = time() + exponential(self.__lambdas['LEGIT'])

        while True:

            # Check if it is time for sending a LEGIT message. If yes then convert it to Sphinx 
            # packet and put on sending queue that's probed via Poisson process.
            if not self.__rawMails.empty() and self.__rawMails.queue[0][0] < time():
                mail   = self.__rawMails.get_nowait()[1]
                splits = self.__msgGenerator(self.__userId, 'LEGIT', mail['size'], self.__lambdas['DELAY'], mail['receiver'])

                for split in splits:
                    self.__messageQueue.put_nowait(split + (len(splits), ))

            # There is a LEGIT message to send.
            if not self.__messageQueue.empty() and timers['LEGIT'] < time():
                data       = self.__messageQueue.get_nowait()
                legitSend  = True
                updateType = 'LEGIT'

            # There is no LEGIT message to send, so send a DROP packet instead and reset the LEGIT
            # traffic timer.
            elif self.__messageQueue.empty() and timers['LEGIT'] < time():
                data       = self.__msgGenerator(self.__userId, 'DROP', self.__bodySize, self.__lambdas['DELAY'], None)[0]
                updateType = 'LEGIT'

            # Generate DROP decoy packet.
            elif timers['DROP'] < time():
                data       = self.__msgGenerator(self.__userId, 'DROP', self.__bodySize, self.__lambdas['DELAY'], None)[0]
                updateType = 'DROP'

            # Generate LOOP decoy packet.
            elif timers['LOOP'] < time():
                data       = self.__msgGenerator(self.__userId, 'LOOP', self.__bodySize, self.__lambdas['DELAY'], None)[0]
                updateType = 'LOOP'

            if data is not None:

                # Unpack the data for sending.
                packet    = data[0]
                nextNode  = data[1]
                msgId     = data[2]
                split     = data[3]
                ofType    = data[4]

                sendPacket(packet, self.__providerPort)

                # Logging.
                timeStr = "{:.7f}".format(time())

                info('%s %s %s %s %s %s', timeStr, self.__userId, nextNode, msgId, split, ofType)

                # Reset the timer for a given message type.
                timers[updateType] = time() + exponential(self.__lambdas[updateType])

                # When LEGIT message was sent inform the optimizer about it through eventQueue.
                if legitSend:
                    self.__eventQueue.put((msgId, timeStr, data[5]))

                    legitSend = False

                # Reset the state.
                data       = None
                updateType = None

            if not self.__cmdQueue.empty():
                cmd = self.__cmdQueue.get()

                # Empty command gracefully terminates the worker.
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