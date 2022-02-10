import json
import pickle

from time import time
from uuid import uuid4
from queue import Queue
from string import digits
from string import punctuation
from string import ascii_letters
from typing import Optional
from typing import Generator
# from logging import info
# from logging import INFO
# from logging import basicConfig
from threading import Thread
from collections import Counter

import toml

from node import Node
from util import send_packet
from model.mail import Mail
from model.packet import Packet
from model.event_log import EventLog

from simpy import Environment
from simpy.util import start_delayed
from simpy.events import Event

from numpy import ceil
from numpy import log2
from numpy import array
from numpy.random import RandomState

from petlib.bn import Bn
from sphinxmix.SphinxParams import SphinxParams
from sphinxmix.SphinxClient import Nenc
from sphinxmix.SphinxClient import rand_subset
from sphinxmix.SphinxClient import pack_message
from sphinxmix.SphinxClient import create_forward_message

EPSILON = 1e-16
TYPE_TO_ID = {'PAYLOAD': 0, 'LOOP': 1, 'DROP': 2, 'LOOP_MIX': 3}
BAR_FORMAT = "{percentage:.1f}%|{bar}| {n:.1f}/{total:.1f} [{elapsed}<{remaining} {postfix}]"
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

        self.__rng = RandomState()
        self.__lag = 2600.0
        self.__layers = 2
        num_providers = 2
        self.__e2e_lag = 2500.0
        self.__lambdas = {}
        nodes_per_layer = 2
        self.__end_time = 0.0
        self.__body_size = 5436
        self.__base_port = 49152
        self.__time_unit = 1.0
        self.__start_time = 0.0
        self.__loop_mix_entropy = False

        if 'lag' in config:
            assert isinstance(config['lag'], (int, float)), 'lag must be number'
            assert config['lag'] >= 0.0, 'lag must be non-negative'

            self.__lag = config['lag']

        if 'layers' in config:
            assert isinstance(config['layers'], int), 'layers must be int'
            assert config['layers'] >= 0, 'layers must be non-negative'

            self.__layers = config['layers']

        if 'e2e_lag' in config:
            assert isinstance(config['e2e_lag'], (int, float)), 'e2e_lag must be number'
            assert config['e2e_lag'] >= 0.0, 'e2e_lag must be non-negative'

            self.__e2e_lag = config['e2e_lag']

        if 'lambdas' in config:
            assert isinstance(config['lambdas'], dict), 'lambdas must be dict'

            lambdas = [isinstance(value, (int, float)) for value in config['lambdas'].values()]

            assert all(lambdas), 'All lambdas must be number'

            lambdas = [value > 0.0 for value in config['lambdas'].values()]

            assert all(lambdas), 'All lambdas must be positive'

            self.__lambdas = config['lambdas']

        if 'rng_seed' in config:
            assert isinstance(config['rng_seed'], int), 'rng_seed must be int'
            assert config['rng_seed'] >= 0, 'rng_seed must be non-negative'

            self.__rng = RandomState(config['rng_seed'])

        if 'body_size' in config:
            assert isinstance(config['body_size'], int), 'body_size must be int'
            assert config['body_size'] > 0, 'body_size must be positive'

            self.__body_size = config['body_size']

        if 'base_port' in config:
            assert isinstance(config['base_port'], int), 'base_port must be int'
            assert config['base_port'] > 0, 'base_port must be positive'

            self.__base_port = config['base_port']

        if 'time_unit' in config:
            assert isinstance(config['time_unit'], (int, float)), 'time_unit must be number'
            assert config['time_unit'] > 0.0, 'time_unit must be positive'

            self.__time_unit = config['time_unit']

        if 'start_time' in config:
            assert isinstance(config['start_time'], (float, int)), 'start_time must be number'
            assert config['start_time'] >= 0.0, 'start_time must be non-negative'

            self.__start_time = config['start_time']
            self.__end_time = config['start_time']

        if 'num_providers' in config:
            assert isinstance(config['num_providers'], int), 'num_providers must be int'
            assert config['num_providers'] > 0, 'num_providers must be positive'

            num_providers = config['num_providers']

        if 'nodes_per_layer' in config:
            assert isinstance(config['nodes_per_layer'], int), 'nodes_per_layer must be int'
            assert config['nodes_per_layer'] > 0, 'nodes_per_layer must be positive'

            nodes_per_layer = config['nodes_per_layer']

        if 'loop_mix_entropy' in config:
            assert isinstance(config['loop_mix_entropy'], bool), 'loop_mix_entropy must be bool'

            self.__loop_mix_entropy = config['loop_mix_entropy']

        # basicConfig(filename=config['log_file'], level=INFO, encoding='utf-8')

        if self.__body_size < 65536:
            self.__add_body = 72
            add_buffer = 36
        else:
            self.__add_body = 74
            add_buffer = 40

        if 1 < self.__layers < 5:
            add_buffer += 1
        elif self.__layers == 5:
            add_buffer += 2
        elif 5 < self.__layers:
            add_buffer += 3

        body_len = self.__body_size + self.__add_body
        header_len = 40 * self.__layers + 77
        self.__params = SphinxParams(body_len=body_len, header_len=header_len)
        self.__pki = {}
        self.__providers = []

        for provider in range(num_providers):
            node_id = f'p{provider:06d}'
            new_node = Node(0, node_id, self.__params, self.__base_port, add_buffer)

            self.__pki[node_id] = new_node
            self.__providers += [node_id]

        for layer in range(1, self.__layers + 1):
            for node in range(nodes_per_layer):
                node_id = f'm{((layer - 1) * nodes_per_layer + node + num_providers):06d}'
                new_node = Node(layer, node_id, self.__params, self.__base_port, add_buffer)

                self.__pki[node_id] = new_node

        self.__per_layer_pki = {}

        for node_id, node in self.__pki.items():
            if node.layer not in self.__per_layer_pki:
                self.__per_layer_pki[node.layer] = []

            self.__per_layer_pki[node.layer] += [node_id]

        with open(config['traces_file'], 'r', encoding='utf-8') as file:
            traces = json.load(file)

        self.__traces = [Mail(x['time'], x['size'], x['sender'], x['receiver']) for x in traces]

        self.__users = []
        self.__senders = []

        for mail in self.__traces:
            self.__users += [mail.sender, mail.receiver]
            self.__senders += [mail.sender]

        self.__users = {user: None for user in sorted(list(set(self.__users)))}
        self.__senders = sorted(list(set(self.__senders)))

        self.__payload_queues = {sender: Queue() for sender in self.__senders}
        self.__latency_tracker = {}

        self.__epsilon = 0.0
        self.__entropy = 0.0
        self.__latency = 0.0
        self.__entropy_sum = 0.0
        self.__latency_sum = 0.0
        self.__latency_num = 0

        if notebook:
            from tqdm.notebook import tqdm
        else:
            from tqdm import tqdm

        self.__tqdm = tqdm

        self.__env = Environment(initial_time=self.__start_time)
        self.__pbar = tqdm(total=len(self.__traces), bar_format=BAR_FORMAT)
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
            assert config['num_senders'] > 1, 'num_senders must be at least 2'

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
                user_id = f'u{(int(1e6) - user_idx - 1):06d}'
                self.__fake_senders += [user_id]
                self.__users[user_id] = f'p{self.__rng.randint(0, high=num_providers):06d}'

        self.__challengers = self.__senders + self.__fake_senders

        self.__rng.shuffle(self.__challengers)

        self.__challengers = self.__challengers[:2]

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

        keys = [('DROP', self.__num_senders), ('PAYLOAD', self.__num_senders)]
        keys += [('LOOP', self.__num_senders), ('DELAY', 1), ('LOOP_MIX', len(self.__pki))]

        for key, divisor in keys:
            if key not in self.__lambdas:
                self.__lambdas[key] = 7.879036505057893

            self.__lambdas[key] /= divisor

        self.__loaded = False
        self.__event_log = EventLog(self.__start_time + self.__e2e_lag)

    def __random_plaintext(self, size: int) -> bytes:
        return bytes(''.join(list(self.__rng.choice(ALL_CHARACTERS, size))), encoding='utf-8')

    def __update_pbar(self):
        if isinstance(self.__termination_event, (int, float)):
            update = round(self.__env.now - self.__end_time - self.__pbar.n, 1)

            self.__pbar.update(update)

        self.__pbar.set_postfix({'E2E': self.__epsilon,
                                 'entropy': self.__entropy,
                                 'latency': self.__latency,
                                 'delivered': self.__latency_num})

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

            if of_type == 'PAYLOAD':
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

        routing = [Nenc((path[0], 0.0, TYPE_TO_ID[of_type]))]
        expected_delay = 0.0

        for dest in path[1:]:
            delay = self.__rng.exponential(self.__lambdas['DELAY'])
            routing += [Nenc((dest, delay, TYPE_TO_ID[of_type]))]
            expected_delay += delay

        message = self.__random_plaintext(size)

        header, delta = create_forward_message(self.__params, routing, keys, destination, message)
        packed = pack_message(self.__params, (header, delta))

        return Packet(packed, path[0], of_type, sender, split, msg_id, num_splits, expected_delay)

    def __payload_wrapper(self, mail: Mail) -> Generator:
        yield start_delayed(self.__env, self.__payload_to_sphinx(mail), mail.time + self.__lag)

    def __payload_to_sphinx(self,
                            mail: Mail,
                            msg_id: Optional[str] = None,
                            start_split: int = 0,
                            event_id: Optional[str] = None) -> Generator:
        start_time = time()

        if event_id is not None and event_id in self.__event_log.payload_to_sphinx:
            del self.__event_log.payload_to_sphinx[event_id]

        sender = mail.sender
        of_type = 'PAYLOAD'
        receiver = mail.receiver
        num_splits = int(ceil(mail.size / self.__body_size))

        if msg_id is None:
            msg_id = uuid4().hex

        def wrapper(split_id: str, size: int) -> Packet:
            return self.__gen_packet(sender, msg_id, of_type, size, split_id, num_splits, receiver)

        for split_idx in range(start_split, num_splits):
            split_size = self.__body_size

            if split_idx == num_splits - 1:
                split_size = mail.size - self.__body_size * (num_splits - 1)

            packet = wrapper(f'{split_idx:05d}', split_size)
            event_id = uuid4().hex

            runtime = time() - start_time
            next_time = runtime + self.__env.now
            self.__event_log.payload_to_sphinx[event_id] = (next_time, mail, msg_id, split_idx)
            self.__event_log.put_on_payload_queue[event_id] = (next_time, sender, packet)

            yield self.__env.process(self.__put_on_payload_queue(sender, packet, runtime, event_id))

            start_time = time()

    def __put_on_payload_queue(self,
                               sender: str,
                               packet: Packet,
                               runtime: float,
                               event_id: str) -> Generator:
        yield self.__env.timeout(runtime)
        del self.__event_log.put_on_payload_queue[event_id]

        if event_id in self.__event_log.payload_to_sphinx:
            del self.__event_log.payload_to_sphinx[event_id]

        self.__payload_queues[sender].put(packet)

    def __challenge_worker(self, num: int) -> Generator:
        while True:
            self.__event_log.challenge_worker[num] = self.__env.now + self.__time_unit

            yield self.__env.timeout(self.__time_unit)
            self.__env.process(self.__send_packet(f'CHALLENGE_{num}'))

    def __decoy_worker(self, of_type: str) -> Generator:
        while True:
            delay = self.__rng.exponential(self.__lambdas[of_type])
            self.__event_log.decoy_wrapper[of_type] = self.__env.now + delay

            yield self.__env.timeout(delay)
            self.__env.process(self.__send_packet(of_type))

    def __sample_sender(self) -> str:
        if self.__client_model == 'ALL_SIMULATION':
            return self.__rng.choice(self.__senders + self.__fake_senders)

        min_senders = [user for user, queue in self.__payload_queues.items() if not queue.empty()]
        num_senders = max(len(min_senders), self.__num_senders)

        if num_senders != self.__actual_senders:
            for key in ['PAYLOAD', 'LOOP', 'DROP']:
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

    def __send_packet(self,
                      of_type: str,
                      data: Optional[Packet] = None,
                      node_id: Optional[str] = None,
                      event_id: Optional[str] = None) -> Generator:
        start_time = time()

        if event_id is not None:
            del self.__event_log.send_packet[event_id]

        if of_type == 'DELAY':
            sender = data.sender
        elif of_type == 'LOOP_MIX':
            sender = self.__rng.choice(list(self.__pki.keys()))
        elif of_type[:-1] == 'CHALLENGE_':
            sender = self.__challengers[int(of_type[-1])]
        else:
            sender = self.__sample_sender()

        if of_type == 'PAYLOAD':
            if sender in self.__senders and not self.__payload_queues[sender].empty():
                data = self.__payload_queues[sender].get()

        if data is None:
            actual_type = of_type

            if of_type in ['PAYLOAD', 'CHALLENGE_0', 'CHALLENGE_1']:
                actual_type = 'DROP'

            msg_id = uuid4().hex
            data = self.__gen_packet(sender, msg_id, actual_type, self.__body_size)

            if of_type == 'CHALLENGE_0':
                data.dist = array([1.0, 0.0, 0.0])
            elif of_type == 'CHALLENGE_1':
                data.dist = array([0.0, 1.0, 0.0])

        packet = data.packet
        next_node = data.next_node
        next_address = self.__pki[next_node].port

        if of_type == 'LOOP_MIX':
            msg_id = data.msg_id
            expected_delay = data.expected_delay
            self.__pki[sender].sending_time[msg_id] = (self.__env.now, expected_delay)

        if of_type == 'DELAY' and data.of_type != 'LOOP_MIX':
            data.dist = self.__pki[node_id].prob_sum / self.__pki[node_id].n
            data.dist = data.dist / sum(data.dist)
            self.__pki[node_id].n -= 1
            self.__pki[node_id].prob_sum = data.dist * self.__pki[node_id].n

            is_non_zero = data.dist[0] > 0.0 and data.dist[1] > 0.0
            is_last_layer = self.__pki[node_id].layer == self.__layers
            is_measure_time = self.__env.now >= self.__start_time + self.__e2e_lag

            if is_non_zero and is_last_layer and is_measure_time:
                new_epsilon = abs(log2(data.dist[0] / data.dist[1]))
                self.__epsilon = 0.01 * new_epsilon + 0.99 * self.__epsilon

                # info('%s %s', f"{self.__env.now:.7f}", str(new_epsilon))
                self.__update_pbar()

        send_packet(packet, next_address)

        event_id = uuid4().hex

        runtime = time() - start_time
        next_time = self.__env.now + runtime
        self.__event_log.process_packet[event_id] = (next_time, of_type, data)

        yield start_delayed(self.__env, self.__process_packet(of_type, data, event_id), runtime)

    def __process_packet(self, of_type: str, data: Packet, event_id: str) -> Generator:
        start_time = time()

        del self.__event_log.process_packet[event_id]

        packet = data.packet
        sender = data.sender
        next_node = data.next_node
        actual_type = data.of_type

        if of_type == 'PAYLOAD' and actual_type == 'PAYLOAD':
            msg_id = data.msg_id
            num_splits = data.num_splits

            if msg_id not in self.__latency_tracker:
                self.__latency_tracker[msg_id] = [num_splits, self.__env.now]

        if of_type == 'DELAY' or (of_type == 'LOOP_MIX' and self.__loop_mix_entropy):
            if of_type == 'LOOP_MIX' and self.__loop_mix_entropy:
                self.__pki[sender].l_t += 1

            self.__entropy_sum -= self.__pki[sender].h_t
            self.__entropy_sum += self.__pki[sender].update_entropy()
            self.__entropy = self.__entropy_sum / len(self.__pki)

            # info('%s %s %s', f"{self.__env.now:.7f}", sender, str(self.__pki[sender].h_t))
            self.__update_pbar()

        outcome = self.__pki[next_node].process_packet(packet)
        event_id = uuid4().hex

        self.__pki[next_node].k_t += 1

        if isinstance(outcome[0], float) and isinstance(outcome[1], Packet):
            if actual_type != 'LOOP_MIX':
                self.__pki[next_node].n += 1
                self.__pki[next_node].prob_sum += data.dist

            delay = outcome[0]
            data = outcome[1]

            runtime = time() - start_time + delay
            next_time = self.__env.now + runtime
            self.__event_log.send_packet[event_id] = (next_time, data, next_node)

            args = ('DELAY', data, next_node, event_id)

            yield start_delayed(self.__env, self.__send_packet(*args), runtime)
        else:
            runtime = time() - start_time
            next_time = self.__env.now + runtime
            self.__event_log.postprocess[event_id] = (next_time,) + outcome + (next_node,)
            args = outcome
            args += (next_node, runtime, event_id)

            yield self.__env.process(self.__postprocess(*args))

    def __postprocess(self,
                      msg_id: str,
                      of_type: str,
                      node_id: str,
                      runtime: float,
                      event_id: str) -> Generator:
        yield self.__env.timeout(runtime)
        del self.__event_log.postprocess[event_id]

        if of_type == 'PAYLOAD':
            self.__latency_tracker[msg_id][0] -= 1

        if of_type == 'PAYLOAD' and self.__latency_tracker[msg_id][0] == 0:
            latency = self.__env.now - self.__latency_tracker[msg_id][1]

            self.__latency_sum += latency
            self.__latency_num += 1
            self.__latency = self.__latency_sum / self.__latency_num

            self.__update_pbar()

            if isinstance(self.__termination_event, Event):
                self.__pbar.update(1)

                if self.__latency_num == len(self.__traces):
                    self.__termination_event.succeed()
                    self.__pbar.close()

        elif of_type == 'LOOP_MIX':
            self.__pki[node_id].postprocess(self.__env.now, msg_id)

    def save(self, save_file: str):
        assert save_file[-4:] == '.pkl', 'Save file must be in pickle format'

        self.__end_time = self.__env.now
        self.__payload_queues = {user: queue.queue for user, queue in self.__payload_queues.items()}

        del self.__env
        del self.__pbar
        del self.__params
        del self.__termination_event

        for node in self.__pki.values():
            node.secret_key = node.secret_key.hex()

            del node.params
            del node.params_dict
            del node.public_key

        with open(save_file, 'wb') as file:
            pickle.dump(self, file)

    def fix_loaded(self):
        body_len = self.__body_size + self.__add_body
        header_len = 40 * self.__layers + 77
        sending_time = self.__end_time - self.__start_time - self.__lag
        payload_queues = {user: (queue, Queue()) for user, queue in self.__payload_queues.items()}
        num_delivered = len([1 for remain, _ in self.__latency_tracker.values() if remain == 0])

        for old_queue, queue in payload_queues.values():
            for item in old_queue:
                queue.put(item)

        self.__env = Environment(initial_time=self.__end_time)
        self.__pbar = self.__tqdm(total=len(self.__traces) - num_delivered, bar_format=BAR_FORMAT)
        self.__params = SphinxParams(body_len=body_len, header_len=header_len)
        self.__payload_queues = {user: queue[1] for user, queue in payload_queues.items()}
        self.__termination_event = self.__env.event()

        params_dict = {(self.__params.max_len, self.__params.m): self.__params}

        for node in self.__pki.values():
            node.params = self.__params
            node.secret_key = Bn().from_hex(node.secret_key)
            node.public_key = self.__params.group.expon(self.__params.group.g, [node.secret_key])
            node.params_dict = params_dict

        for mail in self.__traces:
            if mail.time > sending_time:
                self.__env.process(self.__payload_wrapper(mail))

        for event_id, args in self.__event_log.postprocess.items():
            delay = args[0] - self.__end_time
            delay = fix_delay(delay)
            msg = args[1]
            of_type = args[2]
            node = args[3]

            self.__env.process(self.__postprocess(msg, of_type, node, delay, event_id))

        for event_id, args in self.__event_log.send_packet.items():
            delay = args[0] - self.__end_time
            delay = fix_delay(delay)
            packet = args[1]
            node_id = args[2]

            start_delayed(self.__env, self.__send_packet('DELAY', packet, node_id, event_id), delay)

        for of_type, next_time in self.__event_log.decoy_wrapper.items():
            delay = next_time - self.__end_time
            delay = fix_delay(delay)

            start_delayed(self.__env, self.__send_packet(of_type), delay)
            start_delayed(self.__env, self.__decoy_worker(of_type), delay)

        for event_id, args in self.__event_log.process_packet.items():
            delay = args[0] - self.__end_time
            delay = fix_delay(delay)
            of_type = args[1]
            packet = args[2]

            start_delayed(self.__env, self.__process_packet(of_type, packet, event_id), delay)

        for num, next_time in enumerate(self.__event_log.challenge_worker):
            delay = next_time - self.__end_time
            delay = fix_delay(delay)

            start_delayed(self.__env, self.__send_packet(f'CHALLENGE_{num}'), delay)
            start_delayed(self.__env, self.__challenge_worker(num), delay)

        for event_id, args in self.__event_log.payload_to_sphinx.items():
            delay = args[0] - self.__end_time
            delay = fix_delay(delay)
            mail = args[1]
            msg = args[2]
            split = args[3]

            start_delayed(self.__env, self.__payload_to_sphinx(mail, msg, split, event_id), delay)

        for event_id, args in self.__event_log.put_on_payload_queue.items():
            delay = args[0] - self.__end_time
            delay = fix_delay(delay)
            sender = args[1]
            packet = args[2]

            self.__env.process(self.__put_on_payload_queue(sender, packet, delay, event_id))

        self.__loaded = True

    def run_simulation(self, until: Optional[float] = None):
        assert until is None or until > 0.0, 'until must be positive'

        if not self.__loaded:
            for mail in self.__traces:
                self.__env.process(self.__payload_wrapper(mail))

            for of_type in ['LOOP', 'DROP', 'PAYLOAD', 'LOOP_MIX']:
                self.__env.process(self.__decoy_worker(of_type))

            start_delayed(self.__env, self.__challenge_worker(0), self.__e2e_lag)
            start_delayed(self.__env, self.__challenge_worker(1), self.__e2e_lag)

        threads = [Thread(target=node.listener) for node in self.__pki.values()]

        for thread in threads:
            thread.start()

        if until is None:
            num_delivered = len([1 for remain, _ in self.__latency_tracker.values() if remain == 0])

            self.__pbar.reset(total=len(self.__traces) - num_delivered)
        else:
            self.__pbar.reset(total=until)

            self.__termination_event = self.__end_time + until

        self.__env.run(self.__termination_event)

        if until is not None:
            self.__pbar.update(until - self.__pbar.n)

        self.__pbar.close()

        for node in self.__pki.values():
            send_packet(b'TERMINATE_SIMULATION', node.port)

        for thread in threads:
            thread.join()


def load_simulation(file_name: str) -> Simulator:
    with open(file_name, 'rb') as file:
        simulator = pickle.load(file)

    simulator.fix_loaded()
    return simulator


def fix_delay(delay: float):
    if delay <= 0.0:
        return EPSILON
    return delay
