from argparse import ArgumentParser
from simulator import Simulator

if __name__ == "__main__":
    parser = ArgumentParser()

    parser.add_argument('--config', type=str, default="../../config/config.toml")

    args = parser.parse_args()
    config_file = args.config
    simulator = Simulator(config_file)

    simulator.run_simulation()

    with open('../../logs/logs.log', 'w', encoding='utf-8') as file:
        pass
