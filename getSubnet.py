#!/usr/bin/python3
import socket
import subprocess as sp
import ipaddress
import sys

def ip_to_bits(ip_string):
    to_return = "0b"
    for i in ip_string.split('.'):
        to_return += bin(int(i))[2:].zfill(8)
    return to_return

# not this is totally unportable and relies on the ifconfig unix call
def get_netmask_broadcast(ifname):
    pipe = sp.Popen("ifconfig "+ifname, shell=True, stdout=sp.PIPE).stdout
    output = pipe.read().decode('utf-8').split('\n')
    cleaned_output = [i.strip(' \t').split(' ') for i in output]
    inet_line = []
    for i in cleaned_output: # this should use a regexp
        if i[0] == 'inet':
            inet_line = i
    return inet_line[3],inet_line[5]

def scan_ip(ip_addr,port_range=[9999,10000]): # expects an ip_address object
    print("scanning ip address: " + str(ip_addr))
    #s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # default A_NET,SOCK_STREAM values are used
    for port in range(port_range[0],port_range[1]):
        print('on port: ' + str(port))
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) # default A_NET,SOCK_STREAM values are used
        s.settimeout(.1)
        r = s.connect_ex((str(ip_addr),port))
        if r == 0:
            #r.sendall(bytes('this is a message' + "\n", "utf-8"))
            print(str(ip_addr) + " accept socket connection on port " + str(port))
        s.close()

def get_cidr(hex_mask):
    return bin(int(hex_mask,16)).count('1') # assumes all 1's are leading 0's

def scan_this_network():
    this_ip = socket.getfqdn()[0:13] # anything else is extrainious bs
    this_netmask,this_broadcast = get_netmask_broadcast('en0')
    print("this netmask " + str(this_netmask))
    this_cidr = get_cidr(this_netmask)
    this_min = this_broadcast[0:10] + '0'
    print("this min " + str(this_min))
    local_network = ipaddress.ip_network(this_min+'/'+str(this_cidr))
    print(local_network)
    for addr in local_network.hosts():
        scan_ip(addr)
