import IfConfigData as ifdata
import ipaddress

# this is an internal objec
class InterfaceData():
    """
    Internal object used to store information parsed from ifconfig
    """
    def __init__(self,if_name = 'en0'):
        self.interface_data = ifdata.IfConfigDev(if_name)
        if hasattr(self.interface_data, 'inet'):
            inet_string = self.interface_data.inet.strip('\t\n').split(" ")
            self.inet_addr = inet_string[0]
            self.netmask = self._to_ip_form(int(inet_string[2], 16))
            self.broadcast = inet_string[4]
            self.min_net_addr = self.broadcast.replace('255', '0')
            self.local_network = ipaddress.ip_network(str(self.min_net_addr)
                                                  + '/' + str(self.netmask))
        else:
            print("no inet field conversion to InterfaceData object failed")

    def _to_ip_form(self, ip_integer):
        base = 256
        ret_array = []
        while (ip_integer):
            ret_array.append(ip_integer % base)
            ip_integer = ip_integer // base
        ret_array.reverse()
        return ".".join([str(chunk) for chunk in ret_array])