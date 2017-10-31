/**************************************************
	> File Name:  raw_ping.c
	> Author:     Leuckart
	> Time:       2017-10-29 21:20
**************************************************/

#include "raw_ping.h"

struct sockaddr_in dstAddr;
struct sockaddr_in srcAddr;

pid_t PID;
int numSend=0;
int numRecv=0;
struct timeval Tv_begin;

char sendPacket[ICMP_PACKET_LEN];
char recvPacket[MAX_SIZE];

double TimevalSub(struct timeval a,struct timeval b)
{
	return 1000*(a.tv_sec-b.tv_sec)+(double)(a.tv_usec-b.tv_usec)/1000;
}

void Statistics(int num)
{
	struct timeval tv;
	gettimeofday(&tv,NULL);
	printf("\n--- %s ping statistics ---\n",inet_ntoa(dstAddr.sin_addr));
	printf("%d packets transmitted, %d received, %d%% packet loss, time %.1fms\n",numSend,numRecv,100*(1-numRecv/numSend),TimevalSub(tv,Tv_begin));

	signal(SIGINT, SIG_DFL);
	exit(1);
}

int InitSocket(const char *dst_ip)
{
	struct protoent *protocol;
	if((protocol=getprotobyname("icmp"))==NULL)
	{
		perror("Getprotobyname Error\n");
		exit(1);
	}

	int sockfd;
	if((sockfd=socket(PF_INET,SOCK_RAW,protocol->p_proto))<0)
	{
		perror("Socket Error\n");
		exit(1);
	}

	struct timeval tv;
	tv.tv_sec=1;
	tv.tv_usec =0;
	int maxSize=50*1024;
	setsockopt(sockfd,SOL_SOCKET,SO_RCVTIMEO,&tv,TV_LEN);
	setsockopt(sockfd,SOL_SOCKET,SO_SNDTIMEO,&tv,TV_LEN);
	setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,&maxSize,sizeof(maxSize));

	dstAddr.sin_family=AF_INET;
	dstAddr.sin_addr.s_addr=inet_addr(dst_ip);
	printf("PING %s (%s) %ld bytes of data in ICMP packets.\n",dst_ip,inet_ntoa(dstAddr.sin_addr),IP_PACKET_LEN);

	gettimeofday(&Tv_begin,NULL);
	return sockfd;
}

void IcmpRequest(int sockfd,int sequence)
{
	FillIcmpHdr(sequence);
	if(sendto(sockfd,sendPacket,ICMP_PACKET_LEN,0,(struct sockaddr *)&dstAddr,sizeof(struct sockaddr))<0)
	{
		perror("Sendto Error\n");
		exit(1);
	}
	++numSend;
}

void IcmpReply(int sockfd)
{
	while(1)
	{
		socklen_t len;
		if(recvfrom(sockfd,recvPacket,MAX_SIZE,0,(struct sockaddr *)&srcAddr,&len)<0)
		{
			continue;
		}
		struct iphdr *ip_hdr=(struct iphdr*)(recvPacket);
		struct icmphdr *icmp_hdr=(struct icmphdr *)(recvPacket+IP_HDR_LEN);
		struct timeval *ptr_tv=(struct timeval *)(recvPacket+IP_HDR_LEN+ICMP_HDR_LEN);
		struct timeval tv;
		gettimeofday(&tv,NULL);

		if((icmp_hdr->type==ICMP_ECHOREPLY)&&(icmp_hdr->un.echo.id==htons(PID)))
		{
			++numRecv;
			printf("%ld bytes from %s:\ticmp_seq=%d\tttl=%d\ttime=%.3fms\n",IP_PACKET_LEN,inet_ntoa(dstAddr.sin_addr),ntohs(icmp_hdr->un.echo.sequence ),ip_hdr->ttl,TimevalSub(tv,*ptr_tv));
			break;
		}
	}
}

void FillIcmpHdr(int seq)
{
	struct icmphdr *icmp_hdr=(struct icmphdr *)sendPacket;
	icmp_hdr->type=ICMP_ECHO;
	icmp_hdr->code=0;
	icmp_hdr->checksum=0;
	PID=getpid();
	icmp_hdr->un.echo.id=htons(PID);
	icmp_hdr->un.echo.sequence=htons(seq);

	struct timeval *ptr_tv=(struct timeval *)(((struct icmp *)sendPacket)->icmp_data);
	gettimeofday(ptr_tv,NULL);

	icmp_hdr->checksum=CheckSum((unsigned short*)icmp_hdr,ICMP_PACKET_LEN);
}

unsigned short CheckSum(unsigned short *addr, int len)
{
	unsigned int sum=0;
	unsigned short *w=addr;
	while(len>1)
	{
		sum+=*w++;
		len-=2;
	}
	if(len==1)
	{
		sum+=*w;
	}

	sum=(sum>>16)+(sum&0xffff);
	sum=(sum>>16)+(sum&0xffff);
	return (unsigned short)(~sum);
}


void CloseSocket(int sockfd)
{
	close(sockfd);
}

