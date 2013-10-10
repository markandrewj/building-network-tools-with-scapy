from scapy.all import *
import thread

DNSServerIP = "192.168.205.41"
filter = "udp port 53 and ip dst " + DNSServerIP

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
				spfResp = IP(\
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
				thread.start_new_thread(send, (spfResp,1))
				return "Spoofed DNS Response Sent"
				
			else:
				#make DNS query, capturing the answer and send the answer
				thread.start_new_thread(forwardDNS, (pkt,1))
				return "Orig Sent"

	return getResponse

sniff(filter=filter,prn=DNS_Responder(DNSServerIP))