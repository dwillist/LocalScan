import subprocess as sp
import re

_options_re = r"(?P<key>\toptions)=(?P<value>[^\n]+)"
_flags_re = r": (?P<key>flags)=(?P<value>[^\n]+)"
_ether_re = r"(?P<key>ether) (?P<value>[^\n]+)"
_inet6_re = r"(?P<key>inet6) (?P<value>[^\n]+)"
# inet6attr_re = r"(inet6) ([^ \n\t]+) (prefixlen) ([0-9]+) (secured) (scopeid) ([0-9a-fx]+)"
_inet_re = r"(?P<key>inet) (?P<value>[^\n]+)"
# inetattr_re = r"(inet) ([0-9.]+) (netmask) ([0-9a-fx]+) (broadcast) ([0-9.]+)"
_nd6_options_re = r"(?P<key>nd6 options)=(?P<value>[^\n]+)"
_media_re = r"(?P<key>media): (?P<value>[^\n]+)"
_status_re = r"(?P<key>status): (?P<value>[^\n]+)"
_configuration_re = r"(?P<key>Configuration):\n(?P<value>(\t\t[^\n]+\n)+)"
_member_re = r"(?P<key>member): (?P<value>[\t\t[^\n]+])+"
_re_array = (_options_re, _flags_re, _ether_re, _inet6_re, _inet_re, _nd6_options_re,
             _media_re, _status_re, _configuration_re, _member_re)


class IfConfigDev:
    def __init__(self, interface_name, **kwargs):
        self.interface_name = interface_name
        pipe = sp.Popen("ifconfig " + interface_name, shell=True, stdout=sp.PIPE).stdout
        output = pipe.read().decode('utf-8')
        global _re_array
        for reg_exp in _re_array:
            match_obj_iters = list(re.finditer(reg_exp, output))
            if (len(match_obj_iters) > 0):
                setattr(self,match_obj_iters[0]['key'], match_obj_iters[0]['value'])
                if (len(match_obj_iters) > 1):
                    print("multiple matches only the first will be used" + reg_exp)

class IfConfigCollection():
    def __init__(self): # here we set up our object by parsing the ifconfig data
        pipe = sp.Popen("ifconfig", shell=True, stdout=sp.PIPE).stdout
        output = pipe.read().decode('utf-8')
        # regexp operations
        match_iterators = list(re.finditer(r"([a-zA-z0-9]+): flags=",output))
        self.devices = [m.group(0)[:-8] for m in match_iterators]
        for dev in self.devices:
            setattr(self,dev,IfConfigDev(dev))
