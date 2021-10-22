from time         import time
from time         import sleep
from util         import sendPacket
from queue        import Queue
from queue        import PriorityQueue
from typing       import Callable
from logging      import info
from constants    import LAMBDAS
from constants    import MAX_BODY
from constants    import LEGIT_LAG
from numpy.random import exponential

class Client:

    # userId       - 'u' followed by 6 digit ID string (over 100k users in the training set).
    # rawMails     - a list of LEGIT email objects that the user should send at a particular time 
    #                in the simulation. A single email object is a dictionary, with:
    #                    - time - timestamp relative to the start of LEGIT traffic emission in the 
    #                      network indicates when the message should be sent in the simulation.
    #                    - sender - the ID of the sending user.
    #                    - size - integer, number of bytes in the email's plaintext.
    #                    - receiver - the ID of a single receiving user. The emails that had 
    #                      multiple receivers were split into emails of the same sizes, sending 
    #                      times and senders, but one receiver per email.
    # msgGenerator - wrapper function for generation messages encapsulated in Sphinx packets 
    #                implicitly gives the client access to the PKI info.
    # providerPort - Port at which user's provider listens for a connection.
    def __init__(self, userId : str, rawMails : list, msgGenerator : Callable, providerPort : int):
        self.__userId       = userId
        self.__rawMails     = PriorityQueue()
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
        # be reset. 
        data       = None
        updateType = None

        # Dictionary of times at which the next packet of a given type should be emitted. 
        timers = dict()

        # Sample the initial sending times for messages of a given type.
        timers['DROP' ] = time() + exponential(LAMBDAS['DROP'])
        timers['LOOP' ] = time() + exponential(LAMBDAS['LOOP'])
        timers['LEGIT'] = time() + exponential(LAMBDAS['LEGIT'])

        while True:

            # Check if its time for sending a LEGIT message. If yes then convert it to Sphinx packet
            # and put on sending queue that's probed via Poisson process.
            if not self.__rawMails.empty() and self.__rawMails.queue[0][0] < time():
                mail   = self.__rawMails.get_nowait()[1]
                splits = self.__msgGenerator(self.__userId, 'LEGIT', mail['size'], mail['receiver'])

                for split in splits:
                    self.__messageQueue.put_nowait(split)

            # There is a LEGIT message to send.
            if not self.__messageQueue.empty() and timers['LEGIT'] < time():
                data       = self.__messageQueue.get_nowait()
                updateType = 'LEGIT'

            # There is no LEGIT message to send, so send a DROP packet instead and reset the LEGIT
            # traffic timer.
            elif self.__messageQueue.empty() and timers['LEGIT'] < time():
                data       = self.__msgGenerator(self.__userId, 'DROP', MAX_BODY, None)[0]
                updateType = 'LEGIT'

            # Generate DROP decoy packet.
            elif timers['DROP'] < time():
                data       = self.__msgGenerator(self.__userId, 'DROP', MAX_BODY, None)[0]
                updateType = 'DROP'

            # Generate LOOP decoy packet.
            elif timers['LOOP'] < time():
                data       = self.__msgGenerator(self.__userId, 'LOOP', MAX_BODY, None)[0]
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

                # Reset the state.
                data       = None
                updateType = None

                # Reset the timer for a given message type.
                timers[updateType] = time() + exponential(LAMBDAS[updateType])
            else:
                sleep(0.01)