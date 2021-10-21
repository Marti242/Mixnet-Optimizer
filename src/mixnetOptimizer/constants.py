from string                 import digits
from string                 import punctuation
from string                 import ascii_letters
from sphinxmix.SphinxParams import SphinxParams

LAMBDAS          = dict()
LAMBDAS['DROP' ] = 3 * 7.879036505057893
LAMBDAS['LOOP' ] = 2 * 7.879036505057893
LAMBDAS['LEGIT'] = 2 * 7.879036505057893

MAX_BODY       = 1024
DELAY_MEAN     = 7.879036505057893
LOOP_MIX_LAMB  = 7.879036505057893
SPHINX_PARAMS  = SphinxParams(body_len=MAX_BODY + 63, header_len=250)
ALL_CHARACTERS = list(ascii_letters + digits + punctuation + ' ')

TYPE_TO_ID = {'LEGIT': 0, 'LOOP': 1, 'DROP': 2, 'LOOP_MIX': 3}
ID_TO_TYPE = {0: 'LEGIT', 1: 'LOOP', 2: 'DROP', 3: 'LOOP_MIX'}