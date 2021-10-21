from bson                   import ObjectId
from numpy                  import ceil
from socket                 import socket
from socket                 import AF_INET
from socket                 import SOCK_STREAM
from petlib.bn              import Bn
from petlib.ec              import EcPt
from petlib.ec              import EcGroup
from constants              import MAX_BODY
from constants              import DELAY_MEAN
from constants              import TYPE_TO_ID
from constants              import SPHINX_PARAMS
from constants              import ALL_CHARACTERS
from numpy.random           import choice
from numpy.random           import exponential
from sphinxmix.SphinxClient import Nenc
from sphinxmix.SphinxClient import rand_subset
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import create_forward_message

# Construct random plaintext out of the available characters of required size.
def randomPlaintext(size : int) -> bytes:
    return bytes(''.join(list(choice(ALL_CHARACTERS, size))), encoding='utf-8')

# Convert a hex saved public key in the PKI into petlib public key object.
def publicKeyFromPKI(publicKey : str) -> EcPt:
    return EcPt(EcGroup()).from_binary(Bn.from_hex(publicKey).binary(), EcGroup())

def sendPacket(packet : bytes, nextAddress : int):
    with socket(AF_INET, SOCK_STREAM) as client:
        client.connect(('127.0.0.1', nextAddress))
        client.sendall(packet)
        client.close()

def pkiToPerLayerPKI(pki : dict) -> dict:
    perLayerPKI = dict()

    for nodeId, nodePKI in pki.items():
        if nodePKI['layer'] not in perLayerPKI:
            perLayerPKI[nodePKI['layer']] = dict()

        perLayerPKI[nodePKI['layer']][nodeId] = nodePKI

    return perLayerPKI

def msgWrapper(pki      : dict,
               sender   : str, 
               ofType   : str,
               size     : int  = MAX_BODY,
               users    : dict = None,
               receiver : str  = None    ) -> list:

    # Ensure constraints are satisfied.
    assert  ofType in ['LEGIT', 'DROP', 'LOOP', 'LOOP_MIX']
    assert (ofType != 'LEGIT'    and size      ==     MAX_BODY) or (ofType == 'LEGIT'                         )
    assert (ofType == 'LEGIT'    and receiver  is not None    ) or (ofType != 'LEGIT'    and receiver  is None)
    assert (ofType != 'LOOP_MIX' and users     is not None    ) or (ofType == 'LOOP_MIX' and users     is None)
    assert (ofType != 'LOOP_MIX' and sender[0] ==     'u'     ) or (ofType == 'LOOP_MIX' and sender[0] == 'm' )
    
    msgId       = str(ObjectId())
    splits      = []
    numSplits   = int(ceil(size / MAX_BODY))
    perLayerPKI = pkiToPerLayerPKI(pki)

    wrapper = lambda x, y : makeMsg(sender, ofType, receiver, msgId, x, y, pki, users, perLayerPKI)
    
    for split in range(numSplits):
        splitSize = MAX_BODY
        
        if split == numSplits-1:
            splitSize = size - MAX_BODY * (numSplits-1)
            
        splits += [wrapper(splitSize, split) + (msgId,)]
        
    return splits

def makeMsg(sender      : str, 
            ofType      : str,
            receiver    : str,
            messageId   : str,
            size        : int,
            split       : int,
            pki         : dict,
            users       : dict,
            perLayerPKI : dict) -> tuple :

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

    keys        = [publicKeyFromPKI(pki[nodeId]['publicKey']) for nodeId in path]
    destination = (destination, messageId, split, TYPE_TO_ID[ofType])
    nencWrapper = lambda dest, delay: Nenc((dest, delay, messageId, split, TYPE_TO_ID[ofType]))

    # Add routing information for each mix, sample delays.
    routing = [nencWrapper(dest, exponential(DELAY_MEAN)) for dest in path]

    # Instantiate random message.
    message = randomPlaintext(size) 
    
    params        = SPHINX_PARAMS
    header, delta = create_forward_message(params, routing, keys, destination, message)
    packed        = pack_message(params, (header, delta))

    return packed, path[0]