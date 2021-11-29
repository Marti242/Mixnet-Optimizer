from argparse  import ArgumentParser
from simulator import Simulator

"""
Project entry point. Simulates the mixnet.
"""

if __name__ == "__main__":
    
    # Get command line arguments.
    parser = ArgumentParser()

    parser.add_argument('--config', type=str, default="../../config/config.toml")

    args       = parser.parse_args()
    configFile = args.config
    
    simulator = Simulator(configFile)

    simulator.runSimulation()