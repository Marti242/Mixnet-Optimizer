import json

from time import time
from queue import Queue
from string import digits
from string import punctuation
from string import ascii_letters
from typing import Optional
from typing import Generator
from logging import info
from logging import INFO
from logging import basicConfig
from threading import Thread
from collections import Counter

import toml

from mail import Mail
from node import Node
from util import send_packet
from packet import Packet

from bson import ObjectId
from simpy import Environment
from numpy import ceil
from numpy import array
from numpy.random import RandomState
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import Nenc
from sphinxmix.SphinxClient import rand_subset
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import create_forward_message

TYPE_TO_ID = {'LEGIT': 0, 'LOOP': 1, 'DROP': 2, 'LOOP_MIX': 3}
CLIENT_MODES = ['ALL_SIMULATION', 'TIME_PROXIMITY', 'UNIFORM_PROVIDER']
ALL_CHARACTERS = list(ascii_letters + digits + punctuation + ' ')


class Simulator:
    """SIMULATOR"""

    def __init__(self, config_file: str, notebook: bool = False):
        assert config_file[-5:] == '.toml', 'Config file must be in TOML format'

        with open(config_file, 'r', encoding='utf-8') as file:
            config = toml.load(file)

        assert 'log_file' in config, 'Logging file must be specified'
        assert 'traces_file' in config, 'Traces file must be specified'
        assert isinstance(config['log_file'], str), 'Path to log file must be string'
        assert isinstance(config['traces_file'], str), 'Path to traces file must be string'
        assert config['traces_file'][-5:] == '.json', 'Traces file must be in JSON format'

        layers = 2
        self.__rng = RandomState()
        self.__lag = 10
        num_providers = 2
        self.__lambdas = {}
        nodes_per_layer = 2
        self.__body_size = 5436
        self.__start_time = 0
        self.__loop_mix_entropy = False

        if 'lag' in config:
            assert isinstance(config['lag'], float), 'lag must be float'

            self.__lag = config['lag']

        if 'layers' in config:
            assert isinstance(config['layers'], int), 'layers must be int'

            layers = config['layers']

        if 'lambdas' in config:
            assert isinstance(config['lambdas'], dict), 'lambdas must be dict'

            lambdas = [isinstance(value, float) for value in config['lambdas'].values()]

            assert all(lambdas), 'All lambdas must be float.'

            self.__lambdas = config['lambdas']

        if 'rng_seed' in config:
            assert isinstance(config['rng_seed'], int), 'rng_seed must be int'

            self.__rng = RandomState(config['rng_seed'])

        if 'body_size' in config:
            assert isinstance(config['body_size'], int), 'body_size must be int'

            self.__body_size = config['body_size']

        if 'start_time' in config:
            assert isinstance(config['start_time'], float), 'start_time must be float'

            self.__start_time = config['start_time']

        if 'num_providers' in config:
            assert isinstance(config['num_providers'], int), 'num_providers must be int'

            num_providers = config['num_providers']

        if 'nodes_per_layer' in config:
            assert isinstance(config['nodes_per_layer'], int), 'nodes_per_layer must be int'

            nodes_per_layer = config['nodes_per_layer']

        if 'loop_mix_entropy' in config:
            assert isinstance(config['loop_mix_entropy'], bool), 'loop_mix_entropy must be bool'

            self.__loop_mix_entropy = config['loop_mix_entropy']

        basicConfig(filename=config['log_file'], level=INFO, encoding='utf-8')

        if self.__body_size < 65536:
            add_body = 63
            add_buffer = 36
        else:
            add_body = 65
            add_buffer = 40

        if 0 < layers < 3:
            add_buffer += 1
        elif 2 < layers:
            add_buffer += 3

        header_len = 71 * layers + 108
        self.__params = SphinxParams(body_len=self.__body_size + add_body, header_len=header_len)
        self.__pki = {}
        self.__providers = []

        for provider in range(num_providers):
            node_id = f'p{provider:06d}'
            new_node = Node(0, node_id, self.__params, add_buffer)

            self.__pki[node_id] = new_node
            self.__providers += [node_id]

        for layer in range(1, layers + 1):
            for node in range(nodes_per_layer):
                node_id = f'm{((layer - 1) * nodes_per_layer + node + num_providers):06d}'
                new_node = Node(layer, node_id, self.__params, add_buffer)

                self.__pki[node_id] = new_node

        self.__per_layer_pki = {}

        for node_id, node in self.__pki.items():
            if node.layer not in self.__per_layer_pki:
                self.__per_layer_pki[node.layer] = []

            self.__per_layer_pki[node.layer] += [node_id]

        with open(config['traces_file'], 'r', encoding='utf-8') as file:
            traces = json.load(file)

        traces = [Mail(x['time'], x['size'], x['sender'], x['receiver']) for x in traces]
        self.__traces = traces

        self.__users = []
        self.__senders = []

        for mail in self.__traces:
            self.__users += [mail.sender, mail.receiver]
            self.__senders += [mail.sender]

        self.__users = {user: None for user in sorted(list(set(self.__users)))}
        self.__senders = sorted(list(set(self.__senders)))

        self.__legit_queues = {sender: Queue() for sender in self.__senders}
        self.__latency_tracker = {}

        self.__entropy = 0
        self.__latency = 0
        self.__entropy_sum = 0
        self.__latency_sum = 0
        self.__latency_num = 0

        if notebook:
            from tqdm.notebook import tqdm
        else:
            from tqdm import tqdm

        self.__env = Environment(initial_time=self.__start_time)
        self.__pbar = tqdm(total=len(self.__traces))
        self.__termination_event = self.__env.event()

        self.__client_model = 'ALL_SIMULATION'

        if 'client_model' in config:
            assert isinstance(config['client_model'], str), 'client_model must be string'
            assert config['client_model'] in CLIENT_MODES, 'unknown client_model'

            self.__client_model = config['client_model']

        self.__num_senders = len(self.__senders)

        if self.__client_model == 'TIME_PROXIMITY':
            assert num_providers <= self.__num_senders, 'too many providers'

        if 'num_senders' in config:
            assert isinstance(config['num_senders'], int), 'num_senders must be int'
            assert config['num_senders'] > 0, 'num_senders must be positive'

            if self.__client_model == 'ALL_SIMULATION':
                assert config['num_senders'] >= self.__num_senders, 'not enough senders'
            else:
                assert config['num_senders'] < self.__num_senders, 'too many senders'

            if self.__client_model != 'TIME_PROXIMITY':
                assert num_providers <= config['num_senders'], 'not enough senders'

            self.__num_senders = config['num_senders']

        self.__fake_senders = []
        self.__actual_senders = self.__num_senders

        if len(self.__senders) < self.__num_senders:
            self.__fake_senders = [user for user in self.__users if user not in self.__senders]

            difference = min(len(self.__fake_senders), self.__num_senders - len(self.__senders))

            self.__rng.shuffle(self.__fake_senders)

            self.__fake_senders = self.__fake_senders[:difference]

        difference = self.__num_senders - len(self.__senders) - len(self.__fake_senders)

        if difference > 0:
            max_user_id = max([int(user[1:]) for user in self.__users.keys()])

            assert 1e6 > difference + max_user_id, 'num_senders is too large'

            for user_idx in range(difference):
                user_id = f'u{(1e6 - user_idx - 1):06d}'
                self.__fake_senders += [user_id]
                self.__users[user_id] = f'p{self.__rng.randint(0, high=num_providers):06d}'

        user_ids = list(self.__users.keys())
        num_users = len(self.__users)
        provider_nums = list(range(num_providers))

        self.__rng.shuffle(provider_nums)

        user_to_provider = self.__rng.randint(0, high=num_providers, size=num_users)
        user_to_provider = (provider_nums + list(user_to_provider))[:num_users]

        for idx in range(num_users):
            provider_id_string = f'p{user_to_provider[idx]:06d}'

            self.__users[user_ids[idx]] = provider_id_string

        self.__provider_dist = list(Counter(self.__users.values()).items())
        self.__provider_dist = sorted(self.__provider_dist, key=lambda x: int(x[0][1:]))
        self.__provider_dist = array(list(dict(self.__provider_dist).values()))
        self.__provider_dist = self.__provider_dist / sum(self.__provider_dist)

        keys = [('DROP', self.__num_senders), ('LEGIT', self.__num_senders)]
        keys += [('LOOP', self.__num_senders), ('DELAY', 1), ('LOOP_MIX', len(self.__pki))]

        for key, divisor in keys:
            if key not in self.__lambdas:
                self.__lambdas[key] = 7.879036505057893

            self.__lambdas[key] /= divisor

    def __random_plaintext(self, size: int) -> bytes:
        return bytes(''.join(list(self.__rng.choice(ALL_CHARACTERS, size))), encoding='utf-8')

    def __gen_packet(self,
                     sender: str,
                     msg_id: str,
                     of_type: str,
                     size: int,
                     split: str = f'{0:05d}',
                     num_splits: int = 1,
                     receiver: Optional[str] = None) -> Packet:
        if of_type == 'LOOP_MIX':
            path = []
            layer = self.__pki[sender].layer

            for next_layer in range(layer + 1, len(self.__per_layer_pki)):
                path += rand_subset(self.__per_layer_pki[next_layer], 1)

            for next_layer in range(layer):
                path += rand_subset(self.__per_layer_pki[next_layer], 1)

            path += [sender]
            destination = bytes(sender, encoding='utf-8')
        else:
            path = []
            sender_provider = self.__users[sender]
            destination = None
            receiver_provider = None

            for layer in range(1, len(self.__per_layer_pki)):
                path += rand_subset(self.__per_layer_pki[layer], 1)

            if of_type == 'LEGIT':
                destination = bytes(receiver, encoding='utf-8')
                receiver_provider = self.__users[receiver]
            elif of_type == 'DROP':
                receiver_provider = rand_subset(self.__per_layer_pki[0], 1)[0]
                destination = bytes(receiver_provider, encoding='utf-8')
            elif of_type == 'LOOP':
                destination = bytes(sender, encoding='utf-8')
                receiver_provider = sender_provider

            path = [sender_provider] + path + [receiver_provider]

        keys = [self.__pki[node_id].public_key for node_id in path]
        destination = (destination, msg_id, split, TYPE_TO_ID[of_type])

        def nenc_wrapper(target: str, delay_val: float) -> bytes:
            return Nenc((target, delay_val, msg_id, split, TYPE_TO_ID[of_type]))

        routing = [nenc_wrapper(path[0], 0.0)]
        expected_delay = 0.0

        for dest in path[1:]:
            delay = self.__rng.exponential(self.__lambdas['DELAY'])
            routing += [nenc_wrapper(dest, delay)]
            expected_delay += delay

        message = self.__random_plaintext(size)

        header, delta = create_forward_message(self.__params, routing, keys, destination, message)
        packed = pack_message(self.__params, (header, delta))

        return Packet(packed, path[0], msg_id, split, of_type, sender, expected_delay, num_splits)

    def __put_on_legit_queue(self, mail: Mail) -> Generator:
        yield self.__env.timeout(mail.time + self.__lag)

        start_time = time()
        sender = mail.sender
        receiver = mail.receiver
        msg_id = str(ObjectId())
        num_splits = int(ceil(mail.size / self.__body_size))

        def wrapper(split_id: str, size: int) -> Packet:
            return self.__gen_packet(sender, msg_id, 'LEGIT', size, split_id, num_splits, receiver)

        for split in range(num_splits):
            split_size = self.__body_size

            if split == num_splits - 1:
                split_size = mail.size - self.__body_size * (num_splits - 1)

            packet = wrapper(f"{split:05d}", split_size)

            yield self.__env.timeout(max(0.0, time() - start_time))

            start_time = time()

            self.__legit_queues[sender].put(packet)

    def __simpy_worker(self, of_type: str) -> Generator:
        while True:
            delay = self.__rng.exponential(self.__lambdas[of_type])

            yield self.__env.timeout(delay)
            self.__env.process(self.__worker(of_type))

    def __sample_sender(self) -> str:
        if self.__client_model == 'ALL_SIMULATION':
            return self.__rng.choice(self.__senders + self.__fake_senders)

        min_senders = [user for user, queue in self.__legit_queues.items() if not queue.empty()]
        num_senders = max(len(min_senders), self.__num_senders)

        if num_senders != self.__actual_senders:
            for key in ['LEGIT', 'LOOP', 'DROP']:
                self.__lambdas[key] = self.__lambdas[key] * self.__actual_senders / num_senders

            self.__actual_senders = num_senders

        non_min = [mail for mail in self.__traces if mail.sender not in min_senders]
        all_times = [(mail.sender, abs(mail.time - self.__env.now)) for mail in non_min]
        sender_dist = {}

        for sender, dist in all_times:
            if sender not in sender_dist:
                sender_dist[sender] = []

            sender_dist[sender] += [dist]

        sender_dist = [(sender, min(dists)) for sender, dists in sender_dist.items()]
        sender_dist = sorted(sender_dist, key=lambda x: x[1])
        min_senders += [sender for sender, dist in sender_dist] + self.__fake_senders

        if self.__client_model == 'UNIFORM_PROVIDER':
            provider = self.__rng.choice(self.__providers, p=self.__provider_dist)
            valid = [user for user in min_senders[:num_senders] if self.__users[user] == provider]

            if len(valid) > 0:
                return self.__rng.choice(valid)

            return [user for user in min_senders if self.__users[user] == provider][0]

        min_senders = min_senders[:num_senders]

        return self.__rng.choice(min_senders)

    def __worker(self, of_type: str, data: Optional[Packet] = None) -> Generator:
        start_time = time()

        if of_type == 'DELAY':
            sender = data.sender
        elif of_type == 'LOOP_MIX':
            sender = self.__rng.choice(list(self.__pki.keys()))
        else:
            sender = self.__sample_sender()

        if of_type == 'LEGIT':
            if sender in self.__senders and not self.__legit_queues[sender].empty():
                data = self.__legit_queues[sender].get()

        if data is None:
            actual_type = of_type

            if of_type == 'LEGIT':
                actual_type = 'DROP'

            msg_id = str(ObjectId())
            data = self.__gen_packet(sender, msg_id, actual_type, self.__body_size)

        packet = data.packet
        next_node = data.next_node
        msg_id = data.msg_id
        split = data.split
        actual_type = data.of_type
        next_address = self.__pki[next_node].port

        if of_type == 'LOOP_MIX':
            expected_delay = data.expected_delay
            self.__pki[sender].sending_time[msg_id] = (self.__env.now, expected_delay)

        send_packet(packet, next_address)
        yield self.__env.timeout(max(0., time() - start_time))

        time_str = f"{self.__env.now:.7f}"

        info('%s %s %s %s %s %s', time_str, sender, next_node, msg_id, split, actual_type)

        if of_type == 'LEGIT' and actual_type == 'LEGIT':
            num_splits = data.num_splits

            if msg_id not in self.__latency_tracker:
                self.__latency_tracker[msg_id] = [num_splits, time_str]

        if of_type == 'DELAY' or (of_type == 'LOOP_MIX' and self.__loop_mix_entropy):
            if of_type == 'LOOP_MIX' and self.__loop_mix_entropy:
                self.__pki[sender].l_t += 1

            self.__entropy_sum -= self.__pki[sender].h_t
            self.__entropy_sum += self.__pki[sender].update_entropy()
            self.__entropy = self.__entropy_sum / len(self.__pki)

            self.__pbar.set_postfix({'entropy': self.__entropy, 'latency': self.__latency})

        event = yield self.__env.process(self.__pki[next_node].process_packet(self.__env, packet))

        if isinstance(event[0], float) and isinstance(event[1], Packet):
            delay = event[0]
            data = event[1]
            sender = data.sender

            self.__pki[sender].k_t += 1

            yield self.__env.timeout(delay)
            yield self.__env.process(self.__worker('DELAY', data))
        elif isinstance(event[0], str) and isinstance(event[1], str):
            msg_id = event[0]

            if self.__latency_tracker[msg_id][0] == 1:
                time_str = event[1]
                latency = float(time_str) - float(self.__latency_tracker[msg_id][1])

                self.__latency_sum += latency
                self.__latency_num += 1
                self.__latency = self.__latency_sum / self.__latency_num

                self.__pbar.update(1)
                self.__pbar.set_postfix({'entropy': self.__entropy, 'latency': self.__latency})

                if self.__latency_num == len(self.__traces):
                    self.__termination_event.succeed()
                    self.__pbar.close()
            else:
                self.__latency_tracker[msg_id][0] -= 1

    def run_simulation(self):
        self.__pbar.reset(total=len(self.__traces))

        for mail in self.__traces:
            self.__env.process(self.__put_on_legit_queue(mail))

        for of_type in ['LOOP', 'DROP', 'LEGIT', 'LOOP_MIX']:
            self.__env.process(self.__simpy_worker(of_type))

        threads = [Thread(target=node.listener) for node in self.__pki.values()]

        for thread in threads:
            thread.start()

        self.__env.run(self.__termination_event)

        for node in self.__pki.values():
            send_packet(b'TERMINATE_SIMULATION', node.port)

        for thread in threads:
            thread.join()
