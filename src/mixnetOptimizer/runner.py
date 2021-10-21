from json         import load
from node         import Node
from util         import msgWrapper
from client       import Client
from argparse     import ArgumentParser
from threading    import Thread
from numpy.random import randint

# Creates new mix net with provided number of layers, nodes per each layer and providers.
def createMixnet(layers : int, providers : int, tracesFile : str, nodesPerLayer : int):
    pki              = dict()
    nodes            = []
    clients          = []
    threads          = []
    userIds          = []
    legitTraffic     = dict()
    usersToProviders = dict()

    with open(tracesFile, 'r') as file:
        traces = load(file)

        file.close()

    for mail in traces:
        sender = mail['sender']

        if sender not in legitTraffic:
            legitTraffic[sender] = [mail]
        else:
            legitTraffic[sender] += [mail]

        userIds += [sender, mail['receiver']]

    userIds  = sorted(list(set(userIds)))
    numUsers = len(userIds)

    # Randomly assign each user to a provider.
    users = randint(0, high=providers, size=numUsers)

    # Map a user ID to its provider ID. User ID starts with 'u', provider ID starts with 'p'.
    for idx in range(numUsers):
        providerIdString = "p{:06d}".format(users[idx])

        usersToProviders[userIds[idx]] = providerIdString

    # Instantiate providers and add their info to PKI.
    for provider in range(providers):
        nodeId       = "p{:06d}".format(provider)
        nodes       += [Node(nodeId, layer=0)]
        pki[nodeId]  = nodes[-1].toPKIView()

    # Instantiate each mix and add their info to PKI.
    for layer in range(1, layers + 1):
        for node in range(nodesPerLayer):
            nodeId       = "m{:06d}".format((layer - 1) * nodesPerLayer + node + providers)
            nodes       += [Node(nodeId, layer)]
            pki[nodeId]  = nodes[-1].toPKIView()

    # Propagate the global PKI state to each node.
    for node in nodes:
        node.setPKI(pki)

        threads += [Thread(target=node.start)]

    for userId, mails in legitTraffic.items():
        userMsgGenerator = lambda  x, y, z, w : msgWrapper(pki, x, y, z, usersToProviders, w)

        clients += [Client(userId, mails, userMsgGenerator, pki[usersToProviders[userId]]['port'])]
        threads += [Thread(target=clients[-1].start)]

    # Run the mixnet.
    for thread in threads:
        thread.start()

    # Terminate the mixnet.
    for thread in threads:
        thread.join()

# Get command line arguments.
parser = ArgumentParser()

parser.add_argument('--layers',        type=int, default=2)
parser.add_argument('--providers',     type=int, default=2)
parser.add_argument('--tracesFile',    type=str, default="../../data/sample.json")
parser.add_argument('--nodesPerLayer', type=int, default=2)

args          = parser.parse_args()
layers        = args.layers
providers     = args.providers
tracesFile    = args.tracesFile
nodesPerLayer = args.nodesPerLayer

createMixnet(layers, providers, tracesFile, nodesPerLayer)