#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
	char *dev;	// 사용중인 네트워크 이름
	char *net;	// 네트워크 어드레스
	char *mask;	// 네트워크 mask 어드레스
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;	// IP
	bpf_u_int32 maskp;	//submet mask
	struct in_addr addr;

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

	//addr.s_addr = netp;		
	addr.s_addr = netp;
	net - inet_ntoa(addr);

	if(net == NULL)
	{
		perror("inet_ntoa");
		exit(1);
	}

	printf("NET: %s\n" ,net);

	addr.s_addr = maskp;
	mask = inet_ntoa(addr);

	if(mask == NULL)
	{
		perror("inet_ntoa");
		exit(1);
	}

	printf("MASK: %s\n", mask);
	return 0;
}
