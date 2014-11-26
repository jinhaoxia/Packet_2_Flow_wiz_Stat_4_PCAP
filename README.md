Packet_2_Flow_wiz_Stat_4_PCAP
=============================

Transfer packets to flows with statistics information for pcap files.
Test passed under at most 3GB pcap file and 35M packets with 4GB memory machine.

Usage (Tested in windows 32/64-bit command line):
pkt_to_flow_wiz_stat.exe xxxx.pcap

Other tools:
print_pkt_info.exe
print_pkt_info_as_flow.exe

Notice:
1. A flow contains at least 10 packets is counted as flow.
2. This tool is only used for pcap file, for other files, use editcap.exe to transfer. Also see http://www.netresec.com/?page=Blog&month=2012-11&post=Convert-Endace-ERF-capture-files-to-PCAP