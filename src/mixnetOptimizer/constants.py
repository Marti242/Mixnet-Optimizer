from string                 import digits
from string                 import punctuation
from string                 import ascii_letters
from sphinxmix.SphinxParams import SphinxParams

"""
DEFAULT VALUES
"""

"""
DYNAMIC MIXNET PARAMETERS - can change within a single experiment.
"""

# Parameters of a Poisson process for clients emitting cover traffic.
# 7.879036505057893 is the mean time between two emails being sent in the dataset.
LAMBDAS             = dict()
LAMBDAS['DROP'    ] = 7.879036505057893
LAMBDAS['LOOP'    ] = 7.879036505057893
LAMBDAS['LEGIT'   ] = 7.879036505057893
LAMBDAS['DELAY'   ] = 7.879036505057893
LAMBDAS['LOOP_MIX'] = 7.879036505057893

"""
STATIC MIXNET PARAMETERS - do not change within a single experiment.
"""

# Packet payload size.
MAX_BODY = 1024

# Number of seconds between starting the mixnet and sending first LEGIT message.
LEGIT_LAG = 10

# TO DO:
# Current hardcoded values work empirically.
# Identify formula for Sphinx packet header & body length, given mixnet architecture, so that 
# different message sizes can be tried automatically by the optimizer without human changing the
# hardcoded values in the loop.
# CURRENT SETTING IS NOT ROBUST FOR VARYING MIXNET TOPOLOGIES!!!
SPHINX_PARAMS = SphinxParams(body_len=MAX_BODY + 63, header_len=250)

"""
UTIL
"""

# Poll of characters from which plaintext messages are created.
ALL_CHARACTERS = list(ascii_letters + digits + punctuation + ' ')

# Mapping between human-readable message type for display in logging & compact ids encapsulated
# in Sphinx packet routing information. Metadata is more uniform and takes less space in the packet 
# header. 
TYPE_TO_ID = {'LEGIT': 0, 'LOOP': 1, 'DROP': 2, 'LOOP_MIX': 3}
ID_TO_TYPE = {0: 'LEGIT', 1: 'LOOP', 2: 'DROP', 3: 'LOOP_MIX'}