import string
import socket
import numpy  as np

from petlib.bn              import Bn
from petlib.ec              import EcPt
from petlib.ec              import EcGroup
from sphinxmix.SphinxClient import Nenc
from sphinxmix.SphinxClient import rand_subset
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import create_forward_message

ALL_CHARACTERS = [char for char in string.ascii_letters + string.digits + string.punctuation]

# Construct random plaintext out of the available characters of required size.
def randomPlaintext(size : int):
    return bytes(''.join(list(np.random.choice(ALL_CHARACTERS, size))), encoding='utf-8')

# Convert a hex saved public key in the PKI into petlib public key object.
def publicKeyFromPKI(publicKey : str):
    return EcPt(EcGroup()).from_binary(Bn.from_hex(publicKey).binary(), EcGroup())

def sendPacket(packet : bytes, nextAddress: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(('127.0.0.1', nextAddress))
        client.sendall(packet)
        client.close()

# Create a Sphinx packet of a given type ready for sending through the mix.
# sender      - ID of sending entity, either a user ID ('u#') for LEGIT, DROP or LOOP traffic, 
#               or a mix ID (m#) for LOOP_MIX traffic
# ofType      - the type of message, can be one of four:
#                   - LEGIT
#                   - DROP
#                   - LOOP
#                   - LOOP_MIX
# size        - number of plaintext bytes
# users       - a dictionary that maps a user ID to the ID of the provider at which they are 
#               registered
# perLayerPKI - dictionary of dictionaries maps a layer number to the PKI dictionary for that layer.
#               PKI dictionary maps node ID to its PKI view. Providers are located at the 0th layer.
# params      - SphinxParams object, its parameters can be custom set and provided here, otherwise
#               default values are taken.
# receiver    - Only for LEGIT traffic indicate the ID of the receiver user.
# message     - For debugging - instead of creating random gibberish, pass something readable
#               to check the logs and see if the mixnet works.
def encapsulateMessage(sender      : str, 
                       ofType      : str,
                       size        : int,
                       users       : dict,
                       perLayerPKI : dict,
                       params      : SphinxParams = SphinxParams(),
                       receiver    : str          = None,
                       message     : str          = None):

    # Ensure constraints are satisfied.
    assert  ofType in ['LEGIT', 'DROP', 'LOOP', 'LOOP_MIX']
    assert (ofType == 'LEGIT'    and receiver  is not None) or (ofType != 'LEGIT'    and receiver  is None)
    assert (ofType != 'LOOP_MIX' and sender[0] ==     'u' ) or (ofType == 'LOOP_MIX' and sender[0] == 'm' )

    # Convert the perLayerPKI into a global PKI view.
    pki = dict([node for layer in list(perLayerPKI.values()) for node in layer.items()])

    if ofType == 'LOOP_MIX':
        layer = pki[sender]['layer']
        path  = []

        # Randomly sample one mix per each layer supersisiding mix layer.
        for nextLayer in range(layer + 1, len(perLayerPKI)):
            path += rand_subset(perLayerPKI[nextLayer], 1)

        # Randomly sample a provider and one mix per each layer preceding mix layer.
        for nextLayer in range(layer):
            path += rand_subset(perLayerPKI[nextLayer], 1)

        # Message should return back to sending mix.
        path        += [sender]
        destination  = bytes(sender, encoding='utf-8')
    else:
        senderProvider = users[sender]
        path           = []

        # Sample random path through mix (one mix per each layer)
        for layer in range(1, len(perLayerPKI)):
            path += rand_subset(perLayerPKI[layer], 1)

        if ofType == 'LEGIT':
            destination      = bytes(receiver, encoding='utf-8')
            receiverProvider = users[receiver]
        elif ofType == 'DROP':

            # Sample a random provider and direct the DROP message to it.
            receiverProvider = rand_subset(perLayerPKI[0], 1)[0]
            destination      = bytes(receiverProvider, encoding='utf-8')
        elif ofType == 'LOOP':

            # Direct the LOOP message back to the sender's provider, so it gets back to the sender.
            destination      = bytes(sender, encoding='utf-8')
            receiverProvider = senderProvider

        path = [senderProvider] + path + [receiverProvider]

    keys = [publicKeyFromPKI(pki[nodeId]['publicKey']) for nodeId in path]

    # Add routing information for each mix. For the simulation purposes add also data for logging.
    routing = [Nenc((prev, dest)) for (prev, dest) in zip([None, sender] + path[:-2], path)]

    # Instantiate random message if None was passed.
    if message is None:
        message = randomPlaintext(size) 
    
    header, delta = create_forward_message(params, routing, keys, destination, message)
    packed        = pack_message(params, (header, delta))

    return packed