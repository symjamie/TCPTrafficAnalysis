# TCPTrafficAnalysis
Author:  Yiming Sun
Purpose:  CSc 361 - Assignment 2
Date:  Feb 24, 2018

--------------------------------------------------------------------------

Execution environment:
	Python 3.6 with modules:
		- dpkt
		- socket

--------------------------------------------------------------------------

Input:

A valid trace file in the argument line. (e.g. run the program with "./python3 tcp_traffic_analysis.py sample-capture-file").

--------------------------------------------------------------------------

Output:

The summary information to be computed for each TCP connection includes:

• the state of the connection. Possible states are: S0F0 (no SYN and no FIN), S1F0 (one SYN and no FIN), S2F0 (two SYN and no FIN), S1F1 (one SYN and one FIN), S2F1 (two SYN and one FIN), S2F2 (two SYN and two FIN), S0F1 (no SYN and one FIN), S0F2 (no SYN and two FIN), and so on, as well as R (connection reset due to protocol error). Getting this state information correct is the most important part of your program. We are especially interested in the complete TCP connections for which we see at least one SYN and at least one FIN.
For these complete connections, you can report additional information, as indicated in the following.

• the starting time, ending time, and duration of each complete connection

• the number of packets sent in each direction on each complete connection, as well as the total packets

• the number of data bytes sent in each direction on each complete connection, as well as the total bytes. This byte count is for data bytes (i.e., excluding the TCP and IP protocol headers).
Besides the above information for each TCP connection, your program needs to provide the following statistical results for the whole trace data:

• the number of reset TCP connections observed in the trace

• the number of TCP connections that were still open when the trace capture ended

• the number of complete TCP connections observed in the trace

• Regarding the complete TCP connections you observed:
	
	– the minimum, mean, and maximum time durations of the complete TCP connections
	
	– the minimum, mean, and maximum RTT (Round Trip Time) values of the complete TCP connections
	
	– the minimum, mean, and maximum number of packets (both directions) sent on the complete TCP connections
	
	– the minimum, mean, and maximum receive window sizes (both sides) of the complete TCP connections.

--------------------------------------------------------------------------

Error handlings:
	• Output an error message if the filename is not provided properly;
	• Output an error message if the file can not be opened;
	• Output an error message if the file can not be read as a pcap file.

--------------------------------------------------------------------------

Details about implementations are commented in source code.
