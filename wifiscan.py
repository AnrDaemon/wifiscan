from scapy.all import *

PROBE_REQUEST_TYPE=0
PROBE_REQUEST_SUBTYPE=4

WHITELIST = ['00:00:00:00:00:00',] # Replace this with your phone's MAC address

def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type==PROBE_REQUEST_TYPE and pkt.subtype == PROBE_REQUEST_SUBTYPE and ( pkt.addr2.lower() in WHITELIST or pkt.addr2.upper() in WHITELIST):
            PrintPacket(pkt)

def PrintPacket(pkt):
    print "Probe Request Captured:"
    try:
        extra = pkt.notdecoded
    except:
        extra = None
    if extra!=None:
        signal_strength = -(256-ord(extra[-4:-3]))
    else:
        signal_strength = -100
        print "No signal strength found"    
    print "Target: %s Source: %s SSID: %s RSSi: %d"%(pkt.addr3,pkt.addr2,pkt.getlayer(Dot11ProbeReq).info,signal_strength)

def main():
    from datetime import datetime
    print "[%s] Starting scan"%datetime.now()
    print "Scanning for:"
    print "\n".join(mac for mac in WHITELIST)
    while(True):
        # we limit the count to 100 to prevent memory use from escalating forever
        # once it hits 100 packets sniffed, it will stop the sniffing process,
        # freeing up memory, and then restart the process when the loop restarts
        sniff(iface=sys.argv[1],prn=PacketHandler,count=100)   
    return 1

if __name__=="__main__":
    main()
