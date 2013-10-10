from scapy.all import *
import thread

DNSServerIP = "172.16.20.40"
filter = "udp port 53 and ip dst " + DNSServerIP

def DNS_Responder(localIP):

	def forwardDNS(orig_pkt, num):
		print "Forwarding: " + orig_pkt[DNSQR].qname
		response = sr1(IP(dst="8.8.8.8")/UDP(sport=orig_pkt[UDP].sport)/\
			DNS(rd=1,id=orig_pkt[DNS].id,qd=DNSQR(qname=orig_pkt[DNSQR].qname)))
		respPkt = IP(dst=orig_pkt[IP].src)/UDP(dport=orig_pkt[UDP].sport)/DNS()
		respPkt[DNS] = response[DNS]
		print "Responding: " + respPkt.summary()
		send(respPkt)

	def getResponse(pkt):

		if (DNS in pkt and pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != localIP):
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

	return getResponse

sniff(filter=filter,prn=DNS_Responder(DNSServerIP))