import json
import argparse
import threading
import numpy     as np

from node import Node

# Node worker
class server(threading.Thread):

   def __init__(self, node : Node):
      threading.Thread.__init__(self)
      self.node = node

   def run(self):
       self.node.start()

# Creates new mix net with provided number of layers, nodes per each layer, providers and users.
def createMixnet(layers : int, numUsers : int, providers : int, nodesPerLayer : int):
    pki              = dict()
    nodes            = []
    threads          = []
    usersToProviders = dict()

    # Randomly assign each user to a provider.
    users = np.random.randint(0, high=providers, size=numUsers)

    # Map a user ID to its provider ID. User ID starts with 'u', provider ID starts with 'p'.
    for idx in range(len(users)):
        usersToProviders['u' + str(idx)] = 'p' + str(users[idx])

    # Instantiate providers and add their info to PKI.
    for provider in range(providers):
        nodeId       = 'p' + str(provider)
        nodes       += [Node(nodeId, 0)]
        pki[nodeId]  = nodes[-1].toPKIView()

    # Instantiate each mix and add their info to PKI.
    for layer in range(1, layers + 1):
        for node in range(nodesPerLayer):
            nodeId       = 'm' + str((layer - 1) * nodesPerLayer + node + providers)
            nodes       += [Node(nodeId, layer)]
            pki[nodeId]  = nodes[-1].toPKIView()

    # Propagate the global PKI state to each node.
    for node in nodes:
        node.setPKI(pki)

        threads += [server(node)]

    # For development and debugging only - make the PKI available via JSON file.
    with open('global/pki.json', 'w') as file:
        json.dump(pki, file)
        file.close()

    with open('global/users.json', 'w') as file:
        json.dump(usersToProviders, file)
        file.close()

    # Run the mixnet.
    for thread in threads:
        thread.start()

    # Terminate the mixnet.
    for thread in threads:
        thread.join()

# Get command line arguments.
parser = argparse.ArgumentParser()

parser.add_argument('--layers',        type=int)
parser.add_argument('--numUsers',      type=int)
parser.add_argument('--providers',     type=int)
parser.add_argument('--nodesPerLayer', type=int)

args          = parser.parse_args()
layers        = args.layers
numUsers      = args.numUsers
providers     = args.providers
nodesPerLayer = args.nodesPerLayer

createMixnet(layers, numUsers, providers, nodesPerLayer)