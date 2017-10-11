#!/usr/bin/python3

import NetworkScanner
import IntefaceDataObj
import argparse

def print_list(printlist):
    for elem in printlist:
        print(elem)

parser = argparse.ArgumentParser()
parser.add_argument('protocol',
                    help='protocol to use in scan, must be TCP or PING')
parser.add_argument('--verbose', '-v',
                    action='store_true',
                    help='add debuging output to scan')
parser.add_argument('-n', '--network',
                    help='cidr IPv6 network to scan')

args = parser.parse_args()
if args.verbose:
    pass
if args.network:
    network_arg = args.network
else:
    print("intializing network to local network by parsing ifconfig output")
    network_arg = IntefaceDataObj.InterfaceData().local_network
scanner_instance = NetworkScanner.NetworkScanner(network_arg)
if args.protocol == 'PING':
    print("conducting PING scan of {}".format(network_arg))
    print_list(scanner_instance.ping_sweep())
elif args.protocol == 'TCP':
    print("conducting TCP scan of {}".format(network_arg))
    print_list(scanner_instance.tcp_sweep())
else:
    raise argparse.ArgumentError("must specify protocol PING or TCP")
scanner_instance.__del__()

