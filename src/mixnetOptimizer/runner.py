from simulator import Simulator

if __name__ == "__main__":
    simulator = Simulator('../../config/config.toml')

    simulator.run_simulation(50.0)
