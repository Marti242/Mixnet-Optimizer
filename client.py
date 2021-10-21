
from time         import time
from time         import sleep
from util         import sendPacket
from queue        import Queue
from queue        import PriorityQueue
from typing       import Callable
from constants    import LAMBDAS
from constants    import MAX_BODY
from numpy.random import exponential

class Client:
    def __init__(self, userId : str, rawMails : list, msgCreator : Callable, providerPort : int):
        self.userId       = userId
        self.rawMails     = PriorityQueue()
        self.msgCreator   = msgCreator
        self.messageQueue = Queue()
        self.providerPort = providerPort

        for mail in rawMails:
            self.rawMails.put_nowait((time() + mail['sending_time'], mail))

    def start(self,):
        data            = None
        timers          = dict()
        current         = time()
        updateType      = None
        timers['DROP' ] = current + exponential(LAMBDAS['DROP'])
        timers['LOOP' ] = current + exponential(LAMBDAS['LOOP'])
        timers['LEGIT'] = current + exponential(LAMBDAS['LEGIT'])

        while True:
            if not self.rawMails.empty() and self.rawMails.queue[0][0] < time():
                mail   = self.rawMails.get_nowait()[1]
                splits = self.msgCreator(self.userId, 'LEGIT', mail['size'], mail['receiver'])

                for idx, split in enumerate(splits):
                    self.messageQueue.put_nowait(split + (str(idx), 'LEGIT'))

            if not self.messageQueue.empty() and timers['LEGIT'] < time():
                data       = self.messageQueue.get_nowait()
                updateType = 'LEGIT'

            elif self.messageQueue.empty() and timers['LEGIT'] < time():
                data       = self.msgCreator(self.userId, 'DROP', MAX_BODY, None)[0] + ('0', 'DROP')
                updateType = 'LEGIT'

            elif timers['DROP'] < time():
                data       = self.msgCreator(self.userId, 'DROP', MAX_BODY, None)[0] + ('0', 'DROP')
                updateType = 'DROP'

            elif timers['LOOP'] < time():
                data       = self.msgCreator(self.userId, 'LOOP', MAX_BODY, None)[0] + ('0', 'LOOP')
                updateType = 'LOOP'

            if data is not None:
                packet    = data[0]
                nextNode  = data[1]
                messageId = data[2]
                split     = data[3]
                ofType    = data[4]

                sendPacket(packet, self.providerPort)

                timeString = "{:.7f}".format(time())
                
                print(' '.join([timeString, self.userId, nextNode, messageId, split, ofType]))

                data               = None
                timers[updateType] = time() + exponential(LAMBDAS[updateType])
                updateType         = None
            else:
                sleep(0.01)