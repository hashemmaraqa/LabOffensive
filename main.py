import fire
import dns_spoofing
import arp_poisoning
import ssl_stripping
import iptables_wrapper

def main():
    fire.Fire({'dns_spoofing': dns_spoofing.DNSSpoofing, 'arp_poisoning': arp_poisoning.ARPSpoofer, 'ssl_stripping': ssl_stripping.SSLStripping, 'iptables': iptables_wrapper.IPTablesWrapper})

if __name__ == "__main__":
    main()