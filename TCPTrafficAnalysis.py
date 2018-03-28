# Author:  Yiming Sun
# Date:  Feb 24, 2018
# Last modified: Mar 4, 2018

import sys
import dpkt
import socket

debug = False

class connection:
	def __init__(self):
		self.pktsSent = [] # List of TCP packets ((timestamp, size, TCP)).
		self.pktsRcvd = []
		self.dataSent = 0
		self.dataRcvd = 0
		self.end = -1
		self.dur = -1
		self.S = 0
		self.F = 0


conn = {} # A dictionary maps ID's ((src, sport, dst, dport)) to connection's.
# Statistics for completed connections (with 3-way handshake establishment hand at least one FIN packet, same below).
durs = []
RTTs = []
pkts = []
wins = []


def readPcap(file):
	try:
		f = open(file, "rb")
	except:
		print("ERROR: file \"" + file + "\" does not exist.")
		sys.exit()
	try:
		pcap = dpkt.pcap.Reader(f)
	except:
		print("ERROR: file \"" + file + "\" is not a valid pcap file.")
		sys.exit()
	for ts, buf in pcap:
		ip = dpkt.ethernet.Ethernet(buf).data
		tcp = ip.data
		src = socket.inet_ntoa(ip.src)
		sport = tcp.sport
		dst = socket.inet_ntoa(ip.dst)
		dport = tcp.dport
		# Create new connection when a packet with only SYN flag found.
		if (not (src, sport, dst, dport) in conn) and (not (dst, dport, src, sport) in conn):
			conn[(src, sport, dst, dport)] = connection()
		size = ip.len - (ip.hl + tcp.off) * 4 # Size of TCP payload (exclude sizes of IP and TCP header).
		if (src, sport, dst, dport) in conn: # Sending packet.
			conn[(src, sport, dst, dport)].pktsSent.append((ts, size, tcp))
		else: # Receiving packet.
			conn[(dst, dport, src, sport)].pktsRcvd.append((ts, size, tcp))
	f.close()


def analyzeData():
	global rstConns, compConns
	rstConns = 0
	compConns = 0
	for ID, c in conn.items():
		# Find status and end time (timestamp of last FIN packet if it exist) for each connection (O(n)).
		rsted = False
		winsTemp = [] # Abandoned if connection is not completed.
		for p in c.pktsSent:
			if p[2].flags & 2 ** 0 != 0: # FIN flag is set.
				c.F = c.F + 1
				c.end = p[0]
			if p[2].flags & 2 ** 1 != 0: # SYN flag is set.
				c.S = c.S + 1
			if p[2].flags & 2 ** 2 != 0: # RST flag is set.
				rsted = True
			c.dataSent = c.dataSent + p[1]
			winsTemp.append(p[2].win)
		for p in c.pktsRcvd:
			if p[2].flags & 2 ** 0 != 0:
				c.F = c.F + 1
				c.end = p[0] # Must be greater than the timestamp of the last FIN packet SENT.
			if p[2].flags & 2 ** 1 != 0:
				c.S = c.S + 1
			if p[2].flags & 2 ** 2 != 0:
				rsted = True
			c.dataRcvd = c.dataRcvd + p[1]
			winsTemp.append(p[2].win)
		if rsted == True:
			rstConns = rstConns + 1
		# Analyze completed connection.
		if c.S > 0 and c.F > 0: # The connection is completed.
			# Calculate duration.
			compConns = compConns + 1
			c.dur = c.end - c.pktsSent[0][0]
			durs.append(c.dur)
			# Estimate RTT using method 1 as provided, track from client end (O(n^2)).
			if debug:
				print(ID)
				absStart = conn[next(iter(conn))].pktsSent[0][0]
			for ps in c.pktsSent:
				# ack # = seq # + 1 corresponding to SYN and FIN packet.
				if ps[2].flags & 2 ** 0 != 0 or ps[2].flags & 2 ** 1 != 0:
					offset = 1
				# ack # = seq # + data sent in bytes in data transfer state.
				else:
					offset = ps[1]
				for pr in c.pktsRcvd:
					# Only find ACK packets received AFTER sending corresponding packets.
					if pr[0] < ps[0]:
						continue
					if pr[2].ack == ps[2].seq + offset and pr[2].flags & 2 ** 0 == 0: # Avoid matching passive FIN packets.
						RTTs.append(pr[0] - ps[0]) # Record difference of time stamps.
						if debug:
								print("seq # {} (ts = {}) sent {} bytes, matches ack # {} (ts = {}): RTT = {}".format(ps[2].seq, ps[0] - absStart, ps[1], pr[2].ack, pr[0] - absStart, pr[0] - ps[0]))
						break
			pkts.append(len(c.pktsSent) + len(c.pktsRcvd)) # Calculate total number of packets.
			wins.extend(winsTemp) # Record window sizes.


def printSummary():
	print("\nA) Total number of connections: %d" % len(conn))
	print("\n_______________________________________________________________________________\n")
	print("B) Connections' details:\n")
	absStart = conn[next(iter(conn))].pktsSent[0][0] # The timestamp of the first packet for calculating relative times.
	n = 1
	for ID, c in conn.items():
		if n == 1:
			print()
		else:
			print("+++++++++++++++++++++++++++++++++")
		print("Connection %d:" % n) 
		print("Source Address: " + ID[0])
		print("Destination Address: " + ID[2])
		print("Source Port: %d" % ID[1])
		print("Destination Port: %d" % ID[3])
		print("Status: S{}F{}".format(c.S, c.F))
		if c.S > 0 and c.F > 0:
			# Compute relative start and end time of each connection.
			print("Start time: %.4f s" % (c.pktsSent[0][0] - absStart))
			print("End Time: %.4f s" % (c.end - absStart))
			print("Duration: %.4f s" % c.dur)
			print("Number of packets sent from Source to Destination: %d" % len(c.pktsSent))
			print("Number of packets sent from Destination to Source: %d" % len(c.pktsRcvd))
			print("Total number of packets: %d" % (len(c.pktsSent) + len(c.pktsRcvd)))
			print("Number of data bytes sent from Source to Destination: %d" % c.dataSent)
			print("Number of data bytes sent from Destination to Source: %d" % c.dataRcvd)
			print("Total number of data bytes: %d" % (c.dataSent + c.dataRcvd))
		print("END")
		n = n + 1
	print("\n_______________________________________________________________________________\n")
	print("C) General\n")
	print("Total number of complete TCP connections: %d" % compConns)
	print("Number of reset TCP connections: %d" % rstConns)
	print("Number of TCP connections that were still open when the trace capture ended: %d" % (len(conn) - compConns))
	print("\n_______________________________________________________________________________\n")
	print("D) Complete TCP connections:")
	print("\nMinimum time duration: %.4f s" % min(durs))
	print("Mean time duration: %.4f s" % (sum(durs) / float(len(durs))))
	print("Maximum time duration: %.4f s" % max(durs))
	print("\nMinimum RTT value: %.4f ms" % (min(RTTs) * 1000))
	print("Mean RTT value: %.4f ms" % (sum(RTTs) / float(len(RTTs)) * 1000))
	print("Maximum RTT value: %.4f ms" % (max(RTTs) * 1000))
	print("\nMinimum number of packets including both send/received: %d" % min(pkts))
	print("Mean number of packets including both send/received: %.2f" % (sum(pkts) / float(len(pkts))))
	print("Maximum number of packets including both send/received: %d" % max(pkts))
	print("\nMinimum receive window size including both send/received: %d bytes" % min(wins))
	print("Mean receive window size including both send/received: %.2f bytes" % (sum(wins) / float(len(wins))))
	print("Maximum receive window size including both send/received: %d bytes" % max(wins))
	print("\n_______________________________________________________________________________\n")


def main():
	if not len(sys.argv) == 2:
		print("ERROR: run the program with \"./tcp_traffic_analysis.py <filename>\".")
		sys.exit()
	readPcap(sys.argv[1])
	analyzeData()
	if not debug:
		printSummary()


if __name__ == "__main__":
	main()
