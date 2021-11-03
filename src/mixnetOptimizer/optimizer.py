from json                   import load
from time                   import sleep
from node                   import Node
from util                   import generateMessage
from numpy                  import mean
from queue                  import SimpleQueue
from client                 import Client
from logging                import INFO
from logging                import basicConfig
from threading              import Thread
from numpy.random           import randint
from sphinxmix.SphinxParams import SphinxParams

# Creates new mix net with a provided number of layers, nodes per each layer and providers. 
# A plaintext of a packet in a mix can have at most bodySize of bytes.
# tracesFile - a path to JSON file with legitimate traffic traces that should be emitted 
#              in a simulation. A tracesFile is a list of email objects. Email object is a dict 
#              with:
#                  - time - timestamp, relative to the time at which the messages should start 
#                    to flow.
#                  - sender - the user ID of the sending entity. `u` followed by 6 digit ID string 
#                    (there are over 100k users in the training set).
#                  - size - the number of bytes in a plaintext mail message.
#                  - receiver - the user ID of the receiving entity. The same format as the sender.
def createMixnet(layers        : int, 
                 bodySize      : int, 
                 providers     : int, 
                 tracesFile    : str, 
                 nodesPerLayer : int):

    # Ensure the provided tracesFile is in JSON format.
    assert tracesFile[-5:] == '.json'

    pki     = dict()
    nodes   = []
    clients = []
    threads = []

    # Synchronized queue through which clients and mixes inform the optimizer about the current 
    # level of entropy or the sending and receiving times of LEGIT messages.
    eventQueue = SimpleQueue()

    # Gather info on how many users should be registered in the simulation.
    userIds = []

    # Maps user ID to the legitimate emails that they should send in the simulation. Length of this 
    # dictionary defines the total number of sending clients that should be active at some time 
    # in the simulation.
    legitTraffic = dict()

    # Maps user ID to its provider ID.
    users = dict()

    # Logging configuration. All nodes & clients log to same file.
    basicConfig(filename='../../logs/logs.log', level=INFO, encoding='utf-8')

    # Load the traces file.
    with open(tracesFile, 'r') as file:
        traces = load(file)

        file.close()

    # Parse the dataset.
    for mail in traces:
        sender = mail['sender']

        if sender not in legitTraffic:
            legitTraffic[sender] = [mail]
        else:
            legitTraffic[sender] += [mail]

        userIds += [sender, mail['receiver']]

    # Compute number of unique users.
    userIds  = sorted(list(set(userIds)))
    numUsers = len(userIds)

    # Randomly assign each user to a provider.
    userIdxToProvider = randint(0, high=providers, size=numUsers)

    # Map a user ID to its provider ID. User ID starts with 'u', provider ID starts with 'p', they 
    # are followed by 6 digit ID string (there are over 100k users in the dataset).
    for idx in range(numUsers):
        providerIdString = "p{:06d}".format(userIdxToProvider[idx])

        users[userIds[idx]] = providerIdString

    # Set the global static variables - things that do not change within an experiment. Mainly, the 
    # packet size and other variables that depend on it such as the size of the connection buffer, 
    # size of the packet header and plaintext body.
    if bodySize < 65536:
        addBody   = 63
        addBuffer = 36
    else:
        addBody   = 65
        addBuffer = 40

    if 0 < layers and layers < 3:
        addBuffer += 1
    elif 2 < layers:
        addBuffer += 3
    
    headerLen = 71 * layers + 108
    params    = SphinxParams(body_len=bodySize + addBody, header_len=headerLen)

    # Instantiate providers and add their info to PKI.
    for provider in range(providers):
        nodeId       = "p{:06d}".format(provider)
        nodes       += [Node(0, nodeId, params, bodySize, addBuffer, eventQueue)]
        pki[nodeId]  = nodes[-1].toPKIView()

    # Instantiate each mix and add their info to PKI.
    for layer in range(1, layers + 1):
        for node in range(nodesPerLayer):

            # Mix ID is 'm' followed by 6 digit ID string. Mix IDs do not start at 0, they follow 
            # provider numeration. Node IDs define listening ports, so overall node ID configuration
            # avoids port collisions.
            nodeId       = "m{:06d}".format((layer - 1) * nodesPerLayer + node + providers)
            nodes       += [Node(layer, nodeId, params, bodySize, addBuffer, eventQueue)]
            pki[nodeId]  = nodes[-1].toPKIView()

    threads += [Thread(target=observer, args=(pki, eventQueue))]

    # Propagate the global PKI state to each node.
    for node in nodes:
        node.setPKI(pki)

        threads += [Thread(target=node.start)]

    # Create online clients in the simulation.
    # ASSUMPTION: user that sends at least a single message is active throughout the whole 
    # simulation. The user that receives, but does not send a packet is never online.
    for userId, mails in legitTraffic.items():

        # Wrapper that propagates PKI info to all clients. It is used to encapsulate messages of any
        # type in a set of Sphinx packets.
        # x - user ID.
        # y - the type of message to generate, enum.
        # z - the size of the plaintext message in bytes.
        # w - receiver, an ID of the receiving user for LEGIT traffic.
        usrMsgGen = lambda  x, y, z, w : generateMessage(pki, x, y, params, z, bodySize, users, w)

        providerPort = pki[users[userId]]['port']

        # Instantiate the clients.
        clients += [Client(userId, bodySize, mails, usrMsgGen, providerPort, eventQueue)]
        threads += [Thread(target=clients[-1].start)]

    # TO DO:
    # Control the mixnet. Let the simulation run for a predefined time. Then, send a command through 
    # a synchronized queue to terminate all threads.

    # Run the mixnet.
    for thread in threads:
        thread.start()

    # Terminate the mixnet.
    for thread in threads:
        thread.join()

# Worker that monitors the average level of entropy in the mixnet and computes the E2E latency
# of LEGIT messages.
def observer(pki : dict, eventQueue : SimpleQueue):


    tracker = dict()

    # Stores the E2E latencies of all of the LEGIT messages in the dataset.
    latencies = []

    # Maps the mixnet node to its current level of entropy.
    entropies = dict([(nodeId, 0.) for nodeId in pki])

    while True:
        if not eventQueue.empty():
            event = eventQueue.get()

            # Entropy measurement is delivered.
            if len(event) == 2 and type(event[1]) == float:
                nodeId            = event[0]
                entropy           = event[1]
                entropies[nodeId] = entropy

                # Compute & log the mean entropy across all the nodes.
                print('entropy:', mean(list(entropies.values())))

            # The LEGIT packet was delivered to user's provider.
            elif len(event) == 2:
                msgId = event[0]

                # Check if it is the last split of the message. If yes then compute the overall E2E
                # latency and log the mean latency of all LEGIT messages delivered so far.
                if tracker[msgId][0] == 1:
                    timeStr    = event[1]
                    latencies += [float(timeStr) - float(tracker[msgId][1])]

                    print('latency:', mean(latencies))                    
                    del tracker[msgId]

                # There are still packets of the given message that need to be delivered. Decrement
                # the counter of packets waiting for delivery for the current message.
                else:
                    tracker[msgId][0] -= 1

            # The optimizer is notified that a LEGIT packet was sent by a client.
            else:
                msgId = event[0]

                # The optimizer records the new LEGIT message only once, together with number 
                # of packets to which it was split and the time when first split was sent.
                if msgId not in tracker:
                    timeStr        = event[1]
                    numSplits      = event[2]
                    tracker[msgId] = [numSplits, timeStr]

        else:
            sleep(0.01)
