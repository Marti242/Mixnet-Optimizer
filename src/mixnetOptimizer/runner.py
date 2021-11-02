from argparse  import ArgumentParser
from optimizer import createMixnet

"""
Project entry point. Simulates the mixnet.
"""

if __name__ == "__main__":
    
    # Get command line arguments.
    parser = ArgumentParser()

    parser.add_argument('--layers',        type=int, default=2)
    parser.add_argument('--bodySize',      type=int, default=1024)
    parser.add_argument('--providers',     type=int, default=2)
    parser.add_argument('--tracesFile',    type=str, default="../../data/sample.json")
    parser.add_argument('--nodesPerLayer', type=int, default=2)

    args          = parser.parse_args()
    layers        = args.layers
    bodySize      = args.bodySize
    providers     = args.providers
    tracesFile    = args.tracesFile
    nodesPerLayer = args.nodesPerLayer

    createMixnet(layers, bodySize, providers, tracesFile, nodesPerLayer)