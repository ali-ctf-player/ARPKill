
# 🥾 ARPKill

 █████╗ ██████╗ ██████╗ ██╗  ██╗██╗██╗     ██╗     
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝██║██║     ██║     
███████║██████╔╝██████╔╝█████╔╝ ██║██║     ██║     
██╔══██║██╔═══╝ ██╔═══╝ ██╔═██╗ ██║██║     ██║     
██║  ██║██║     ██║     ██║  ██╗██║███████╗███████╗
╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
           ARP KILL  -  Disconnect Devices


## 📖 Description
**ARPKill** is a Python-based tool that demonstrates **ARP spoofing/poisoning** attacks to disconnect devices from a local network.  
It can target a specific victim and gateway, poison their ARP caches, and capture traffic in the process.  

⚠️ **Disclaimer**: This tool is for **educational and research purposes only**.  
Do **NOT** use it on networks you do not own or have explicit permission to test. Unauthorized usage is illegal.  

---

## ✨ Features
- 🎨 ASCII banner for cool startup
- 🖧 Automatic MAC address discovery
- 💀 Disconnect devices from the LAN
- 🛠️ Restores network on exit (CTRL+C)
- 📡 Packet sniffer + PCAP file output

---

## 🚀 Usage
python ARPKill.py <victim ip> <gateway ip>

---

## 1️⃣ Install dependencies
```bash
pip install scapy
