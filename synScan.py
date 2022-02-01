from scapy.all import IP,ICMP,TCP,sr1
import sys, signal, pyperclip

def exit(sig,frame):
	print('\n[!] Wait...')
	sys.exit(1)

signal.signal(signal.SIGINT,exit)

def icmp_probe(ip):
    icmp_packet = IP(dst=ip)/ICMP()
    resp_packet = sr1(icmp_packet, timeout=10,verbose=False)
    return resp_packet != None

def syn_scan(ip):
    port_list = []
    for port in range(65536):
    	syn_packet = sr1(IP(dst=ip)/TCP(dport=port,flags='S'),verbose=False)
    	resp_packet = syn_packet
        
    	if resp_packet.getlayer('TCP').flags == 'SA':
    	    print(f'[!] The port {port} is open')
    	    port_list.append(port)
    	else:
    	    continue
    
    print(f'\n[!] Open Ports: {port_list}') 
     

if __name__ == '__main__':
    try:
        ip = sys.argv[1]

        if icmp_probe(ip):
            print(f"\n[!] The host {ip} it's active\n")
            syn_scan(ip)
        else:
            print('ICMP Probe Failed')
            
    except IndexError:
    	print('\n [!] Usage: sudo python3 synScan.py <IP>')
