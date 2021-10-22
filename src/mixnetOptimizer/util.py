from bson                   import ObjectId
from numpy                  import ceil
from socket                 import socket
from socket                 import AF_INET
from socket                 import SOCK_STREAM
from petlib.bn              import Bn
from petlib.ec              import EcPt
from petlib.ec              import EcGroup
from constants              import LAMBDAS
from constants              import MAX_BODY
from constants              import TYPE_TO_ID
from constants              import SPHINX_PARAMS
from constants              import ALL_CHARACTERS
from numpy.random           import choice
from numpy.random           import exponential
from sphinxmix.SphinxClient import Nenc
from sphinxmix.SphinxClient import rand_subset
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import create_forward_message

"""
PRIVATE
"""

# Construct random plaintext out of the available characters of required size.
def __randomPlaintext(size : int) -> bytes:
    return bytes(''.join(list(choice(ALL_CHARACTERS, size))), encoding='utf-8')

# Convert a hex saved public key in the PKI into petlib public key object.
def __publicKeyFromPKI(publicKey : str) -> EcPt:
    return EcPt(EcGroup()).from_binary(Bn.from_hex(publicKey).binary(), EcGroup())

# Convert a PKI dictionary into a dictionary of dictionaries in which each mixnet layer 
# is a separate dictionary of mixes' PKI information. Used for sampling a path - selecting one mix 
# per layer.
def __pkiToPerLayerPKI(pki : dict) -> dict:
    perLayerPKI = dict()

    for nodeId, nodePKI in pki.items():
        if nodePKI['layer'] not in perLayerPKI:
            perLayerPKI[nodePKI['layer']] = dict()

        perLayerPKI[nodePKI['layer']][nodeId] = nodePKI

    return perLayerPKI

# Generates a single Sphinx packet of a given type and size.
# split       - ordinal number for reordering purposes in string format (5 digit string <#####>).
# sender      - ID of sending entity either a user (u<######>) or mix (m<######>).
# ofType      - enum, 'LEGIT', 'DROP', 'LOOP' or 'LOOP_MIX'.
# receiver    - ID of receiving entity, only valid for LEGIT traffic, a user (u<######>). For other 
#               types of the receiver is implicitly defined.
# messageId   - message Id - string in the pymongo ObjectId format.
# size        - number of plaintext bytes, should be different than default only if the message 
#               is of LEGIT type.
# pki         - dictionary maps node ID (mix or provider) to its PKI info (listening port, public 
#               key, layer).
# users       - dictionary, maps user ID to its provider ID.
# perLayerPKI - pki dictionary converted via __pkiToPerLayerPKI method
# return      - Tuple of Sphinx packet with information for logging:
#                   - packet.
#                   - next Node to which packet should be forwarded.
#                   - message Id - string in the pymongo ObjectId format.
#                   - split - ordinal number for reordering the purpose in string format (5 digit 
#                     string <#####>).
#                   - type of message.
def __genPckt(split       : str,
              sender      : str, 
              ofType      : str,
              receiver    : str,
              messageId   : str,
              size        : int,
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

    keys        = [__publicKeyFromPKI(pki[nodeId]['publicKey']) for nodeId in path]
    destination = (destination, messageId, split, TYPE_TO_ID[ofType])
    nencWrapper = lambda dest, delay: Nenc((dest, delay, messageId, split, TYPE_TO_ID[ofType]))

    # Add routing information for each mix, sample delays.
    routing = [nencWrapper(dest, exponential(LAMBDAS['DELAY'])) for dest in path]

    # Instantiate random message.
    message = __randomPlaintext(size) 
    
    params        = SPHINX_PARAMS
    header, delta = create_forward_message(params, routing, keys, destination, message)
    packed        = pack_message(params, (header, delta))

    return packed, path[0], messageId, split, ofType

"""
PUBLIC
"""

# Instantiates random message of a given type and converts it to a set of Sphinx packets ready for 
# sending through a mix network. Responsible for splitting a message into chunks. All chunks/splits 
# of the same message have the same message ID, message ID together with split number must be used 
# to identify a packet uniquely sole message ID is not enough.
# pki      - dictionary maps node ID (mix or provider) to its PKI info (listening port, public key, 
#            layer).
# sender   - ID of sending entity either a user (u<######>) or mix (m<######>). mix accepted only 
#            when a packet is of LOOP_MIX type.
# ofType   - enum, 'LEGIT', 'DROP', 'LOOP' or 'LOOP_MIX'.
# size     - number of plaintext bytes, can be different than default only if the message 
#            is of LEGIT type.
# users    - dictionary, maps user ID to its provider ID.
# receiver - ID of receiving entity, only valid for LEGIT traffic, a user (u<######>). For other 
#            types of the receiver is implicitly defined.
# return   - a list of packets with logging data. If the size of the message is larger than MAX_BODY
#            then it is split. Each split is encapsulated in a separate Sphinx packet. Thus, return 
#            a message as a set of packets. When the type of the message is different than LEGIT 
#            always only one packet in a list is returned. Only for LEGIT, more packets can be 
#            returned. A single packet is a tuple:
#                - packet.
#                - next Node to which packet should be forwarded.
#                - message ID - string in the pymongo ObjectId format.
#                - split - ordinal number for reordering the purpose in string format (5 digit 
#                  string <#####>).
#                - type of message.
def generateMessage(pki      : dict,
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
    
    msgId      = str(ObjectId())
    splits     = []
    numSplits  = int(ceil(size / MAX_BODY))
    layeredPKI = __pkiToPerLayerPKI(pki)

    # x - split     - ordinal number for reordering purposes in string format (5 digit string 
    #                 <#####>).
    # y - splitSize - integer, the byte size of the packet to generate.
    wrapper = lambda x, y : __genPckt(x, sender, ofType, receiver, msgId, y, pki, users, layeredPKI)
    
    for split in range(numSplits):
        splitSize = MAX_BODY
        
        # Only the last packet in a too big message can have a non-default size.
        if split == numSplits-1:
            splitSize = size - MAX_BODY * (numSplits-1)

        splits += [wrapper("{:05d}".format(split), splitSize)]
        
    return splits

def sendPacket(packet : bytes, nextAddress : int):
    with socket(AF_INET, SOCK_STREAM) as client:
        client.connect(('127.0.0.1', nextAddress))
        client.sendall(packet)
        client.close()