all: pcap

pcap :	pcap
	gcc -o pcap pcap.c -lpcap -I/usr/include/pcap

clean :
	rm -rf pcap
