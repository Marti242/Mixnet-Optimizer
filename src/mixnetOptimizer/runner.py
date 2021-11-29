from argparse  import ArgumentParser
from simulator import Simulator

if __name__ == "__main__":
    
    parser = ArgumentParser()

    parser.add_argument('--config', type=str, default="../../config/config.toml")

    args       = parser.parse_args()
    configFile = args.config
    
    simulator = Simulator(configFile)

    simulator.runSimulation()