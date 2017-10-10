import NetworkScanner
import IntefaceDataObj
import parser


def main():
    # set up logger for logging scan errors
    localinterface = IntefaceDataObj.InterfaceData()
    n = NetworkScanner.NetworkScanner(localinterface.local_network)
    for task in n.tcp_sweep():
        print(task)

main()
