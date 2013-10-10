from scapy.all import *
import thread

DNSServerIP = "192.168.205.41"

def DNS_Responder(localIP):

	def forwardDNS(orig_pkt, num):
		print orig_pkt[DNSQR].qname
		print orig_pkt.show
		respPkt = sr1(IP(dst="8.8.8.8")/UDP()/\
			DNS(rd=1,qd=DNSQR(qname=orig_pkt[DNSQR].qname)))
		respPkt[0][IP].dst = orig_pkt[IP].src
		respPkt[0][IP].src = localIP
		respPkt[0][UDP].dport = orig_pkt[UDP].sport
		respPkt[0][DNS].id = orig_pkt[DNS].id
		print respPkt.show
		send(respPkt)

	def getResponse(pkt):

		if (DNS in pkt and pkt[DNS].opcode == 0L):
			if "trailers.apple.com" in pkt['DNS Question Record'].qname:
				print pkt.show
				respat = IP(\
					dst=pkt[IP].src)\
					/UDP(\
					dport=pkt[UDP].sport,\
					sport=53\
					)/DNS(\
					id=pkt[DNS].id,\
					qr=1L,\
					opcode=pkt[DNS].opcode,\
					aa=pkt[DNS].aa,\
					tc=pkt[DNS].tc,\
					rd=pkt[DNS].rd,\
					ra=1L,\
					rcode=0L,\
					qdcount=1,\
					ancount=1,\
					nscount=0,\
					arcount=0,\
					qd=pkt[DNS].qd,\
					an=DNSRR(\
					rrname=pkt[DNSQR].qname,\
					type=1,\
					rclass=1,\
					ttl=20,\
					rdata=localIP\
					)/DNSRR(\
					rrname="trailers.apple.com",\
					type=1,\
					rclass=1,
					ttl=20,\
					rdata=localIP\
					))
				print respat.show()
				thread.start_new_thread(send, (respat,1))
				return "Spoof Sent"
				
			else:
				#make DNS query, capturing the answer and send the answer
				thread.start_new_thread(forwardDNS, (pkt,1))
				return "Orig Sent"

	return getResponse

sniff(filter="udp port 53 and ip host 192.168.200.206",prn=DNS_Responder(DNSServerIP))

# >>> d[0]
# <Ether  dst=00:50:56:a2:22:9a src=a8:20:66:29:a6:85 type=0x800 
# <IP  version=4L ihl=5L tos=0x0 len=71 id=8168 flags= frag=0L ttl=255 proto=udp chksum=0x0 src=192.168.201.203 dst=192.168.200.2 options=[] 
# <UDP  sport=62047 dport=domain len=51 chksum=0x1364 
# <DNS  id=7193 qr=0L opcode=QUERY aa=0L tc=0L rd=1L ra=0L z=0L rcode=ok qdcount=1 ancount=0 nscount=0 arcount=0 qd=<DNSQR  qname='e3191.dscc.akamaiedge.net.' qtype=AAAA qclass=IN 
# > an=None ns=None ar=None 
# >>>>
# >>> d[1]
# <Ether  dst=a8:20:66:29:a6:85 src=00:50:56:a2:22:9a type=0x800 
# <IP  version=4L ihl=5L tos=0x0 len=127 id=28456 flags=DF frag=0L ttl=128 proto=udp chksum=0x7826 src=192.168.200.2 dst=192.168.201.203 options=[] 
# <UDP  sport=domain dport=62047 len=107 chksum=0xb62e 
# <DNS  id=7193 qr=1L opcode=QUERY aa=0L tc=0L rd=1L ra=1L z=0L rcode=ok qdcount=1 ancount=2 nscount=0 arcount=0 qd=<DNSQR  qname='e3191.dscc.akamaiedge.net.' qtype=AAAA qclass=IN 
# > an=<DNSRR  rrname='e3191.dscc.akamaiedge.net.' type=AAAA rclass=IN ttl=20 rdata='2600:1406:1a:18d::c77' 
# <DNSRR  rrname='e3191.dscc.akamaiedge.net.' type=AAAA rclass=IN ttl=20 rdata='2600:1406:1a:18b::c77' 
# >> ns=None ar=None 
# >>>>