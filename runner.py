
from json         import dump
from node         import Node
from argparse     import ArgumentParser
from threading    import Thread
from numpy.random import randint

# Creates new mix net with provided number of layers, nodes per each layer, providers and users.
def createMixnet(layers : int, numUsers : int, providers : int, nodesPerLayer : int):
    pki              = dict()
    nodes            = []
    threads          = []
    usersToProviders = dict()

    # Randomly assign each user to a provider.
    users = randint(0, high=providers, size=numUsers)

    # Map a user ID to its provider ID. User ID starts with 'u', provider ID starts with 'p'.
    for idx in range(len(users)):
        userIdString     = "u{:02d}".format(idx)
        providerIdString = "p{:02d}".format(users[idx])

        usersToProviders[userIdString] = providerIdString

    # Instantiate providers and add their info to PKI.
    for provider in range(providers):
        nodeId       = "p{:02d}".format(provider)
        nodes       += [Node(nodeId, layer=0)]
        pki[nodeId]  = nodes[-1].toPKIView()

    # Instantiate each mix and add their info to PKI.
    for layer in range(1, layers + 1):
        for node in range(nodesPerLayer):
            nodeId       = "m{:02d}".format((layer - 1) * nodesPerLayer + node + providers)
            nodes       += [Node(nodeId, layer)]
            pki[nodeId]  = nodes[-1].toPKIView()

    # Propagate the global PKI state to each node.
    for node in nodes:
        node.setPKI(pki)

        threads += [Thread(target=node.start)]

    # For development and debugging only - make the PKI available via JSON file.
    with open('global/pki.json', 'w') as file:
        dump(pki, file)
        file.close()

    with open('global/users.json', 'w') as file:
        dump(usersToProviders, file)
        file.close()

    # Run the mixnet.
    for thread in threads:
        thread.start()

    # Terminate the mixnet.
    for thread in threads:
        thread.join()

# Get command line arguments.
parser = ArgumentParser()

parser.add_argument('--layers',        type=int, default=2)
parser.add_argument('--numUsers',      type=int, default=2)
parser.add_argument('--providers',     type=int, default=2)
parser.add_argument('--nodesPerLayer', type=int, default=2)

args          = parser.parse_args()
layers        = args.layers
numUsers      = args.numUsers
providers     = args.providers
nodesPerLayer = args.nodesPerLayer

createMixnet(layers, numUsers, providers, nodesPerLayer)