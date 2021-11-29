import json
import toml

from node                   import Node
from time                   import time
from time                   import sleep
from bson                   import ObjectId
from numpy                  import ceil
from numpy                  import log2
from numpy                  import mean
from sched                  import scheduler
from queue                  import Queue
from socket                 import socket
from socket                 import AF_INET
from socket                 import SOCK_STREAM
from string                 import digits
from string                 import punctuation
from string                 import ascii_letters
from logging                import info
from logging                import INFO
from logging                import basicConfig
from petlib.bn              import Bn
from petlib.ec              import EcPt
from petlib.ec              import EcGroup
from threading              import Thread
from numpy.random           import choice
from numpy.random           import randint
from numpy.random           import exponential
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import Nenc
from sphinxmix.SphinxClient import rand_subset
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import create_forward_message

TYPE_TO_ID     = {'LEGIT': 0, 'LOOP': 1, 'DROP': 2, 'LOOP_MIX': 3}
ALL_CHARACTERS = list(ascii_letters + digits + punctuation + ' ')

class Simulator:

    def __init__(self, configFile : str):
        assert configFile[-5:]  == '.toml', 'Config file must be in TOML format.'  

        with open(configFile, 'r') as file:
            config = toml.load(file)

            file.close()

        assert 'logFile'    in config,                                                                                                                                'Logging file must be specified.'
        assert 'tracesFile' in config,                                                                                                                                'Traces file must be specified.'
        assert type(config['logFile'   ]) == str,                                                                                                                     'Path to log file must be a string.'
        assert type(config['tracesFile']) == str,                                                                                                                     'Path to traces file must be a string.'
        assert config['tracesFile'][-5:]  == '.json',                                                                                                                 'Traces file must be in JSON format.'
        assert 'bodySize'       not in config or  type(config['layers'        ]) == int,                                                                              'layers must be an integer.'
        assert 'maxSimTime'     not in config or  type(config['maxSimTime'    ]) == float,                                                                            'maxSimTime must be a float.' 
        assert 'numProviders'   not in config or  type(config['numProviders'  ]) == int,                                                                              'numProviders must be an integer.'
        assert 'nodesPerLayer'  not in config or  type(config['nodesPerLayer' ]) == int,                                                                              'nodesPerLayer must be an integer.'
        assert 'loopMixEntropy' not in config or  type(config['loopMixEntropy']) == bool,                                                                             'loopMixEntropy must be a boolean.'
        assert 'lambdas'        not in config or (type(config['lambdas'       ]) == dict and all([type(value) == float for value in config['lambdas'   ].values()])), 'All Lambads must be float.'
        assert 'priorities'     not in config or (type(config['priorities'    ]) == dict and all([type(value) == int   for value in config['priorities'].values()])), 'All priorities must be int.'

        layers                = 2
        self.__lag            = 10
        numProviders          = 2
        nodesPerLayer         = 2
        self.__lambdas        = dict()
        self.__bodySize       = 5436
        self.__priorities     = dict()
        self.__loopMixEntropy = False

        if 'lag' in config:
            self.__lag = config['lag']

        if 'layers' in config:
            layers = config['layers']

        if 'lambdas' in config:
            self.__lambdas = config['lambdas']

        if 'bodySize' in config:
            self.__bodySize = config['bodySize']

        if 'priorities' in config:
            self.__priorities = config['priorities']

        if 'numProviders' in config:
            numProviders = config['numProviders']

        if 'nodesPerLayer' in config:
            nodesPerLayer = config['nodesPerLayer']

        if 'loopMixEntropy' in config:
            nodesPerLayer = config['loopMixEntropy']

        basicConfig(filename=config['logFile'], level=INFO, encoding='utf-8')

        with open(config['tracesFile'], 'r') as file:
            self.__traces = json.load(file)

            file.close()

        self.__maxSimTime = self.__traces[-1]['time'] * 2 + self.__lag

        if 'maxSimTime' in config:
            self.__maxSimTime = config['maxSimTime']

        self.__users   = []
        self.__senders = []

        for mail in self.__traces:
            self.__users   += [mail['sender'], mail['receiver']]
            self.__senders += [mail['sender']]

        self.__users   = dict([(user, None) for user in sorted(list(set(self.__users)))])
        self.__senders = sorted(list(set(self.__senders)))

        userIds           = list(self.__users.keys())
        numUsers          = len(self.__users)
        userIdxToProvider = randint(0, high=numProviders, size=numUsers)

        for idx in range(numUsers):
            providerIdString = "p{:06d}".format(userIdxToProvider[idx])

            self.__users[userIds[idx]] = providerIdString

        if self.__bodySize < 65536:
            addBody   = 63
            addBuffer = 36
        else:
            addBody   = 65
            addBuffer = 40

        if 0 < layers and layers < 3:
            addBuffer += 1
        elif 2 < layers:
            addBuffer += 3

        headerLen     = 71 * layers + 108
        self.__params = SphinxParams(body_len=self.__bodySize + addBody, header_len=headerLen)

        self.__pki        = dict()
        self.__nodes      = []
        self.__cmdQueue   = Queue(maxsize=1)
        self.__eventQueue = Queue()

        for provider in range(numProviders):
            nodeId     = "p{:06d}".format(provider)
            params     = self.__params
            cmdQueue   = self.__cmdQueue
            eventQueue = self.__eventQueue

            newNode = Node(0, nodeId, params, cmdQueue, addBuffer, eventQueue)

            self.__nodes       += [newNode]
            self.__pki[nodeId]  = newNode.toPKIView()

        for layer in range(1, layers + 1):
            for node in range(nodesPerLayer):
                nodeId     = "m{:06d}".format((layer - 1) * nodesPerLayer + node + numProviders)
                params     = self.__params
                cmdQueue   = self.__cmdQueue
                eventQueue = self.__eventQueue

                newNode = Node(layer, nodeId, params, cmdQueue, addBuffer, eventQueue)

                self.__nodes       += [newNode]
                self.__pki[nodeId]  = newNode.toPKIView()
            
        self.__perLayerPKI = dict()

        for nodeId, nodePKI in self.__pki.items():
            if nodePKI['layer'] not in self.__perLayerPKI:
                self.__perLayerPKI[nodePKI['layer']] = dict()

            self.__perLayerPKI[nodePKI['layer']][nodeId] = nodePKI

        numSenders = len(self.__senders)

        keys  = [('DROP', numSenders), ('LOOP', numSenders), ('LEGIT', numSenders), ('DELAY', 1)]
        keys += [('LOOP_MIX', len(self.__pki))]

        if 'RAW' not in self.__priorities:
            self.__priorities['RAW'] = 1

        for key, divisor in keys:
            if key not in self.__lambdas:
                self.__lambdas[key] = 7.879036505057893
            
            self.__lambdas[key] /= divisor

            if key not in self.__priorities:
                self.__priorities[key] = 1

        self.__entropyDict = dict()

        for nodeId in self.__pki:
            self.__entropyDict[nodeId] = {'h': 0, 'k': 0, 'l': 0}

        self.__legitQueue     = Queue()
        self.__messageQueue   = scheduler(time, sleep)
        self.__latencyTracker = dict()

    def __randomPlaintext(self, size : int) -> bytes:
        return bytes(''.join(list(choice(ALL_CHARACTERS, size))), encoding='utf-8')

    def __publicKeyFromPKI(self, publicKey : str) -> EcPt:
        return EcPt(EcGroup()).from_binary(Bn.from_hex(publicKey).binary(), EcGroup())

    def __genPckt(self, 
                  split     : str,
                  sender    : str, 
                  ofType    : str,
                  receiver  : str,
                  messageId : str,
                  size      : int) -> tuple :

        if ofType == 'LOOP_MIX':
            path  = []
            layer = self.__pki[sender]['layer']

            for nextLayer in range(layer + 1, len(self.__perLayerPKI)):
                path += rand_subset(self.__perLayerPKI[nextLayer], 1)

            for nextLayer in range(layer):
                path += rand_subset(self.__perLayerPKI[nextLayer], 1)

            path        += [sender]
            destination  = bytes(sender, encoding='utf-8')
        else:
            path           = []
            senderProvider = self.__users[sender]

            for layer in range(1, len(self.__perLayerPKI)):
                path += rand_subset(self.__perLayerPKI[layer], 1)
            if ofType == 'LEGIT':
                destination      = bytes(receiver, encoding='utf-8')
                receiverProvider = self.__users[receiver]
            elif ofType == 'DROP':
                receiverProvider = rand_subset(self.__perLayerPKI[0], 1)[0]
                destination      = bytes(receiverProvider, encoding='utf-8')
            elif ofType == 'LOOP':
                destination      = bytes(sender, encoding='utf-8')
                receiverProvider = senderProvider

            path = [senderProvider] + path + [receiverProvider]

        keys        = [self.__publicKeyFromPKI(self.__pki[nodeId]['publicKey']) for nodeId in path]
        destination = (destination, messageId, split, TYPE_TO_ID[ofType])
        nencWrapper = lambda dest, delay: Nenc((dest, delay, messageId, split, TYPE_TO_ID[ofType]))

        routing       = []
        expectedDelay = 0

        for dest in path:
            delay          = exponential(self.__lambdas['DELAY'])
            routing       += [nencWrapper(dest, delay)]
            expectedDelay += delay

        message = self.__randomPlaintext(size) 
        
        header, delta = create_forward_message(self.__params, routing, keys, destination, message)
        packed        = pack_message(self.__params, (header, delta))

        return packed, path[0], messageId, split, ofType, expectedDelay

    def __generateMessage(self, sender : str, ofType : str, size : int, receiver : str = None) -> list:
        assert  ofType in ['LEGIT', 'DROP', 'LOOP', 'LOOP_MIX']
        assert (ofType != 'LEGIT'    and size      ==     self.__bodySize) or (ofType == 'LEGIT'                               )
        assert (ofType == 'LEGIT'    and receiver  is not None           ) or (ofType != 'LEGIT'    and receiver  is None      )
        assert (ofType != 'LOOP_MIX' and sender[0] ==     'u'            ) or (ofType == 'LOOP_MIX' and sender[0] in ['m', 'p'])
        
        msgId     = str(ObjectId())
        splits    = []
        wrapper   = lambda x, y : self.__genPckt(x, sender, ofType, receiver, msgId, y)
        numSplits = int(ceil(size / self.__bodySize))
        
        for split in range(numSplits):
            splitSize = self.__bodySize
            
            if split == numSplits-1:
                splitSize = size - self.__bodySize * (numSplits-1)

            splits += [wrapper("{:05d}".format(split), splitSize)]
            
        return splits

    def __sendPacket(self, packet : bytes, nextAddress : int):
        try:
            with socket(AF_INET, SOCK_STREAM) as client:
                client.connect(('127.0.0.1', nextAddress))
                client.sendall(packet)
                client.close()
        except:
            print('ERROR')

    def __putOnLegitQueue(self, sender : str, size : int, receiver : str):
        splits = self.__generateMessage(sender, 'LEGIT', size, receiver)

        for split in splits:
            self.__legitQueue.put(split + (sender, len(splits)))

    def __worker(self, ofType : str, data : tuple = None):
        assert  ofType in self.__lambdas.keys()
        assert (ofType != 'DELAY' and data is None) or (ofType == 'DELAY' and data is not None)

        if ofType == 'LEGIT':
            if not self.__legitQueue.empty():
                data = self.__legitQueue.get()

        if data is None:
            actualType = ofType

            if ofType == 'LEGIT':
                actualType = 'DROP'

            if ofType != 'LOOP_MIX':
                sender = choice(self.__senders)
            else:
                sender = choice(list(self.__pki.keys()))

            data = self.__generateMessage(sender, actualType, self.__bodySize)[0] + (sender, )

        packet      = data[0]
        nextNode    = data[1]
        msgId       = data[2]
        split       = data[3]
        actualType  = data[4]
        sender      = data[6]
        nextAddress = self.__pki[nextNode]['port']

        self.__sendPacket(packet, nextAddress)

        timeStr = "{:.7f}".format(time())

        info('%s %s %s %s %s %s', timeStr, sender, nextNode, msgId, split, actualType)

        if ofType == 'LEGIT' and actualType == 'LEGIT':
            numSplits = data[7]

            if msgId not in self.__latencyTracker:
                self.__latencyTracker[msgId] = [numSplits, timeStr, None]

        if ofType != 'DELAY':
            delay    = exponential(self.__lambdas[ofType])
            worker   = Thread(target=self.__worker, args=(ofType, )).start
            priority = self.__priorities[ofType]

            self.__messageQueue.enter(delay, priority, worker)

        if ofType == 'DELAY' or (ofType == 'LOOP_MIX' and self.__loopMixEntropy):
            if ofType == 'LOOP_MIX' and self.__loopMixEntropy:
                self.__entropyDict[sender]['l'] += 1

            Thread(target=self.__updateEntropy, args=(sender,)).start()

    def __updateEntropy(self, nodeId : str):
        h = self.__entropyDict[nodeId]['h']
        k = self.__entropyDict[nodeId]['k']
        l = self.__entropyDict[nodeId]['l']

        denominator = (k + l)
        h_t         = l * h / denominator

        if k != 0:
            h_t += k * log2(k) / denominator
            h_t -= k / denominator * log2(k / denominator)

        if l != 0:
            h_t -= l / denominator * log2(l / denominator)

        self.__entropyDict[nodeId]['h'] = h_t
        self.__entropyDict[nodeId]['l'] = l + k - 1
        self.__entropyDict[nodeId]['k'] = 0

        print('entropy:', mean(list([ent['h'] for ent in self.__entropyDict.values()])))

    def runSimulation(self,):
        threads  = [Thread(target=node.start) for node in self.__nodes]
        threads += [Thread(target=self.__messageQueue.run)]

        rawPriority = self.__priorities['RAW']

        for mail in self.__traces:
            worker      = Thread(target=self.__putOnLegitQueue, kwargs=mail).start
            sendingTime = mail['time'] + self.__lag

            del mail['time']
            self.__messageQueue.enter(sendingTime, rawPriority, worker)

        for ofType in ['LOOP', 'DROP', 'LEGIT', 'LOOP_MIX']:
            delay    = exponential(self.__lambdas[ofType])
            worker   = Thread(target=self.__worker, args=(ofType, )).start
            priority = self.__priorities[ofType]

            self.__messageQueue.enter(delay, priority, worker)

        startTime = time()

        for thread in threads:
            thread.start()

        latencies = []

        while time() < startTime + self.__maxSimTime and len(latencies) < len(self.__traces):
            event = self.__eventQueue.get()

            if type(event[0]) == float and type(event[1]) == tuple:
                delay    = event[0]
                data     = event[1]
                sender   = data[6]
                priority = self.__priorities['DELAY']

                self.__entropyDict[sender]['k'] += 1

                worker = Thread(target=self.__worker, args=('DELAY', data)).start

                self.__messageQueue.enter(delay, priority, worker)
            elif type(event[0]) == str and type(event[1]) == str:
                msgId = event[0]

                if self.__latencyTracker[msgId][0] == 1:
                    timeStr = event[1]
                    latency = float(timeStr) - float(self.__latencyTracker[msgId][1])

                    self.__latencyTracker[msgId][2] = latency

                    latencies = [t[2] for t in self.__latencyTracker.values() if t[2] is not None]

                    print('latency:', mean(latencies), len(latencies))
                else:
                    self.__latencyTracker[msgId][0] -= 1

        for event in self.__messageQueue.queue:
            self.__messageQueue.cancel(event)

        self.__cmdQueue.put(None)

        for thread in threads:
            thread.join()

        

