#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct ip *iph;
struct tcphdr *tcph;

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
	static int count = 1;
	struct ether_header *ep;
	unsigned short ether_type;
	int chcnt =0;
	int length=pkthdr->len;

	ep = (struct ether_header *)packet;
	packet += sizeof(struct ether_header);
	ether_type = ntohs(ep->ether_type);

	if (ether_type == ETHERTYPE_IP)
	{
		iph = (struct ip *)packet;
		printf("IP 패킷\n");
		printf("Version		: %d\n", iph->ip_v);
		printf("Header Len	: %d\n", iph->ip_hl);
		printf("Src Address	: %s\n", inet_ntoa(iph->ip_src));
		printf("Dst Address	: %s\n", inet_ntoa(iph->ip_dst));

		if (iph->ip_p == IPPROTO_TCP)
		{
			tcph = (struct tcp *)(packet + iph->ip_hl * 4);
			printf("Src Port : %d\n", ntohs(tcph->source));
			printf("Dst port : %d\n", ntohs(tcph->dest));
		}

		while(length--)
		{
			printf("%02x", *(packet++));
			if ((++chcnt % 16) == 0)
				printf("\n");
		}
	}
	else
	{
		printf("NONE IP 패킷\n");
	}
	printf("\n\n");
}

int main(int argc, char **argv)
{
	char *dev;	// 사용중인 네트워크 이름
	char *net;	// 네트워크 어드레스
	char *mask;	// 네트워크 mask 어드레스
	
	char errbuf[PCAP_ERRBUF_SIZE];
	int ret;
	struct pcap_pkthdr hdr;
	bpf_u_int32 netp;	// IP
	bpf_u_int32 maskp;	//submet mask
	struct in_addr net_addr, mask_addr;
	struct ether_header *eptr;
	const u_char *packet;

	struct bpf_program fp;

	pcap_t *pcd;

	//네트워크 디바이스 이름을 얻어온다.
	dev = pcap_lookupdev(errbuf);

	//에러가 발생했을경우
	if(dev == NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	//네트워크 디바이스 이름 출력
	printf("DEV: %s\n" ,dev);

	//네트워크 디바이스 이름 dev에 대한 mask, ip 정보 얻어오기
	ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

	if(ret == -1)
	{
		printf("%s\n" ,errbuf);
		exit(1);
	}

	net_addr.s_addr = netp;
	net = inet_ntoa(net_addr);
	printf("NET : %s\n", mask);

	pcd = pcap_open_live(dev, BUFSIZ, NONPROMISCUOUS, -1, errbuf);
	if (pcd ==NULL)
	{
		printf("%s\n", errbuf);
		exit(1);
	}

	if(pcap_compile(pcd, &fp, argv[2], 0, netp) == -1)
	{
		printf("compile error\n");
		exit(1);
	}
	
	if (pcap_setfilter(pcd, &fp) == -1)
	{
		printf("setfilter errpr\n");
		exit(1);
	}

  pcap_loop(pcd, atoi(argv[1]), callback, NULL);
}
	
//	pcap_loop(pcd, atoi(argv[1]), callback, NULL);
//}
