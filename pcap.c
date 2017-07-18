#include "pcap.h"
#define ETHER_ADDR_LEN 6

typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

struct ether_header{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
}eth;

typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char ver_ihl;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
	u_char proto;
	ip_address saddr;
	ip_address daddr;
}ip_header;

typedef struct tcp_header{
	u_short sport;
	u_short dport;
	u_int seqnum;
	u_int acknum;
	u_char th_off;
	u_char flags;
	u_short crc;
}tcp_header;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[]="";
	struct bpf_program fcode;
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error dev: %s\n", errbuf);
		exit(1);
	}

	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

	if ((adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "\nUnble to open the adapter. %s in not supported by WinPcap\n", d->name);

	pcap_freealldevs(alldevs);
	return -1;
	}

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) <0 )
	{
		fprintf(stderr, "\nUnable to compile the packet fileter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the fileter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n패킷 수신중 %s...\n", d->description);

	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);
	return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	unsigned int ptype;

#define IP_HEADER 0x0800

	mac* destmac;
	mac* srcmac;

	destmac = (mac*)pkt_data;
	srcmac = (mac*)(pkt_data + 6);

	struct ether_header* eth;
	eth=(struct ether_header*)pkt_data;
	
	ptype=ntohs(eth->ether_type);

	ip_header * ih;
	u_int ip_len;
	ih=(ip_header*)(pkt_data+14);
	ip_len=(ih->ver_ihl & 0xf) *4;

	printf("eth.dmac: %02x:%02x:%02x:%02x:%02x:%02x \n",
		destmac->byte1,
		destmac->byte2,
		destmac->byte3,
		destmac->byte4,
		destmac->byte5,
		destmac->byte6);
	printf("eth.smac: %02x:%02x:%02x:%02x:%02x:%02x: \n",
		srcmac->byte1,
		srcmac->byte2,
		srcmac->byte3,
		srcmac->byte4,
		srcmac->byte5,	
		srcmac->byte6);

	if(ntohs(eth->ether_type) == IP_HEADER){
		printf("---------- IP HEADER-----------\n");
		printf("ip length is %d\n",(ih->ver_ihl & 0xf)*4);
		printf("ip.dip: %d.%d.%d.%d \n",
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4);
		printf("ip.sip: %d.%d.%d.%d \n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4);

	if(ih->proto==6){
		printf("TCP 프로토콜\n");
		tcp_header *th;
		th=(tcp_header*)((u_char*)ih+ip_len);

#define SYN 0x02
#define PUSH 0x08
#define ACK 0x10
#define SYN_ACK 0x12
#define PUSH_ACK 0x18
#define FIN_ACK 0x11

			printf("TCP Header\n");
			printf("dport : %d\n",ntohs(th->dport));
			printf("sport : %d\n",ntohs(th->sport));
		
			if((th->flags) == SYN)
				printf("Flags : SYN \n");
			else if((th->flags) == PUSH)
				printf("Flags : PUSH \n");
			else if((th->flags) == ACK)
				printf("Flags : ACK \n");
			else if((th->flags) == SYN_ACK)
				printf("Flags : SYN, ACK \n");
			else if((th->flags) == PUSH_ACK)
				printf("Flags :PUSH, ACK \n");
			else if((th->flags) == FIN_ACK)
				printf("Flags :FIN, ACK \n");
			else
				printf("Flags : UnKnown) : %04x\n", th->flags);
		}
		else if(ih->proto==17)
			printf("UDP 프로토콜\n");
		else
			printf("UDP UnKKnown\n");
	}
	else{
		printf("---------- IP 헤더가 없습니다. ----------\n");
	}
	printf("-------------------------------\n");
}
