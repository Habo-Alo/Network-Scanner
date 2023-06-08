from scapy.all import ARP, Ether, srp

def network_scan(ip):
    # Create an ARP request packet
    arp_request = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=0)[0]

    # Extract the IP and MAC addresses from the response
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

# Example usage: scanning the local network
ip_address = "192.168.1.0/24"
scan_result = network_scan(ip_address)

# Display the scan results
if scan_result:
    print("Scanning results:")
    print("IP\t\t\tMAC Address")
    print("-----------------------------------")
    for client in scan_result:
        print(f"{client['ip']}\t\t{client['mac']}")
else:
    print("No devices found.")
