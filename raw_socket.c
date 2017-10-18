/**************************************************
	> File Name:  raw_socket.c
	> Author:     Leuckart
	> Time:       2017-10-17 14:55
**************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#define BUFFER_MAX 2048

#include <linux/ip.h>

void IP(char *ip);

void ARP(char *arp);

void RARP(char *rarp);

int main(int argc,char* argv[])
{
	int sock_fd;
	int proto;
	int n_read;
	char buffer[BUFFER_MAX];
	char *eth_head;
	char *ip_head;
	char *tcp_head;//no use??
	char *udp_head;
	char *icmp_head;
	unsigned char *p;
	if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
	{
		printf("error create raw socket\n");
		return -1;
	}
	while(1)
	{
		n_read = recvfrom(sock_fd,buffer,2048,0,NULL,NULL);
		if(n_read < 42)
		{
			printf("error when recv msg \n");
			return -1;
		}
		eth_head=buffer;
		struct ethhdr *eth_hd = (struct ethhdr *)buffer;
		p = eth_head;
		printf("MAC address1: %.2x:%02x:%02x:%02x:%02x:%02x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",eth_hd->h_source[0],eth_hd->h_source[1],eth_hd->h_source[2],eth_hd->h_source[3],eth_hd->h_source[4],eth_hd->h_source[5],eth_hd->h_dest[0],eth_hd->h_dest[1],eth_hd->h_dest[2],eth_hd->h_dest[3],eth_hd->h_dest[4],eth_hd->h_dest[5]);

		printf("MAC address2: %.2x:%02x:%02x:%02x:%02x:%02x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",p[6],p[7],p[8],p[9],p[10],p[11],p[0],p[1],p[2],p[3],p[4],p[5]);
		
		unsigned char *all_head = eth_head+14;

		//printf("IP:%d.%d.%d.%d==> %d.%d.%d.%d\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
		//proto = (ip_head + 9)[0];
		unsigned char *eth_type = eth_head +12;
		//printf("Protocol:");

		switch(eth_type[0])
		{
			case 0x08:
				if(eth_type[1]==0x00)
				{
					IP(all_head);
				}
				if(eth_type[1]==0x06)
				{
					ARP(all_head);
				}
				break;
			case 0x80:
				if(eth_type[1]==0x35)
				{
					RARP(all_head);
				}
				break;
			default:
				break;
		}

	}
	return -1;
}

struct IPAddress
{
	int one;
	int two;
	int three;
	int four;
};

struct IPAddress GetAddress(__be32 num)
{
	struct IPAddress addr;
	addr.one=num%256;//>0?num%256:num%256+256;
	num/=256;
	addr.two=num%256;//>0?num%256:num%256+256;
	num/=256;
	addr.three=num%256;//>0?num%256:num%256+256;
	num/=256;
	addr.four=num%256;//>0?num%256:num%256+256;
	return addr;
}

void IP(char *ip)
{
	struct iphdr *header=(struct iphdr *)(ip);
	struct IPAddress srcIP=GetAddress(header->saddr);
	struct IPAddress destIP=GetAddress(header->daddr);

	printf("IP1:%d.%d.%d.%d==>%d.%d.%d.%d\n",srcIP.one,srcIP.two,srcIP.three,srcIP.four,destIP.one,destIP.two,destIP.three,destIP.four);

	unsigned char *p=ip+12;
	printf("IP2:%d.%d.%d.%d==> %d.%d.%d.%d\n",p[0],p[1],p[2],p[3],p[4],p[5],p[6],p[7]);
	printf("Protocol:");
	switch(header->protocol)
	{// in in.h

		case IPPROTO_IP:/* Dummy protocol for TCP		*/
			printf("ip\n");
			break;
		case IPPROTO_ICMP:/* Internet Control Message Protocol	*/
			printf("icmp\n");
			break;
		case IPPROTO_IGMP:/* Internet Group Management Protocol	*/
			printf("igmp\n");
			break;
		case IPPROTO_IPIP:/* IPIP tunnels (older KA9Q tunnels use 94) */
			printf("ipip\n");
			break;
		case IPPROTO_TCP:/* Transmission Control Protocol	*/
			printf("tcp\n");
			break;
		case IPPROTO_EGP:/* Exterior Gateway Protocol		*/
			printf("egp\n");
			break;
		case IPPROTO_PUP:/* PUP protocol				*/
			printf("pup\n");
			break;
		case IPPROTO_UDP:/* User Datagram Protocol		*/
			printf("udp\n");
			break;
		case IPPROTO_IDP:/* XNS IDP protocol			*/
			printf("idp\n");
			break;
		case IPPROTO_TP:/* SO Transport Protocol Class 4	*/
			printf("tp\n");
			break;
		case IPPROTO_DCCP:/* Datagram Congestion Control Protocol */
			printf("dccp\n");
			break;
		case IPPROTO_IPV6:/* IPv6-in-IPv4 tunnelling		*/
			printf("icmp\n");
			break;
		case IPPROTO_RSVP:/* RSVP Protocol			*/
			printf("igmp\n");
			break;
		case IPPROTO_GRE:/* Cisco GRE tunnels (rfc 1701,1702)	*/
			printf("ipip\n");
			break;
		case IPPROTO_ESP:/* Encapsulation Security Payload protocol */
			printf("icmp\n");
			break;
		case IPPROTO_AH:/* Authentication Header protocol	*/
			printf("igmp\n");
			break;
		case IPPROTO_MTP:/* Multicast Transport Protocol		*/
			printf("ipip\n");
			break;
		case IPPROTO_BEETPH:/* IP option pseudo header for BEET	*/
			printf("icmp\n");
			break;
		case IPPROTO_ENCAP:/* Encapsulation Header			*/
			printf("igmp\n");
			break;
		case IPPROTO_PIM:/* Protocol Independent Multicast	*/
			printf("ipip\n");
			break;

		case IPPROTO_COMP:/* Compression Header Protocol		*/
			printf("ipip\n");
			break;
		case IPPROTO_SCTP:/* Stream Control Transport Protocol	*/
			printf("ipip\n");
			break;
		case IPPROTO_UDPLITE:/* UDP-Lite (RFC 3828)			*/
			printf("ipip\n");
			break;
		case IPPROTO_MPLS:/* MPLS in IP (RFC 4023)		*/
			printf("ipip\n");
			break;
		case IPPROTO_RAW:/* Raw IP packets			*/
			printf("ipip\n");
			break;
		default:
			printf("please query yourself\n");
	}
	//shun xu huan yi xia
	printf("Header Length:%d\n",header->ihl);
	printf("Version:%d\n",header->version);
	printf("Total Length:%d\n",header->tot_len);
	printf("ID:%d\n",header->id);
	printf("TTL:%d\n",header->ttl);
}

void ARP(char *arp)
{
	unsigned char *p=arp;
	printf("Protocal:ARP\n");
	short temp=(p[0]<<8)+p[1];
	printf("Format of Heardware Type:0x%02x\n",temp);

	p=p+2;
	temp=(p[0]<<8)+p[1];
	printf("Format of Protocol Type:0x%04x\n",temp);

	p=p+2;
	temp=(p[0]);
	printf("Length of Hardware Address:0x%d\n",temp);

	p=p+1;
	temp=(p[0]);
	printf("Length of Protocol Address:0x%d\n",temp);

	p=p+1;
	temp=(p[0]<<8)+p[1];
	if(temp==0x1) 
		printf("Operation:ARP request\n");
	else 
		printf("Operation:ARP responce\n");

	p=p+2;
	printf("Sender Mac Address:%.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=p+6;
	printf("Sender IP Address:%d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
	p=p+4;
	printf("Target Mac Address:%.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=p+6;
	printf("Target IP Address:%d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
}

void RARP(char *rarp)
{
	unsigned char *p=rarp;

	printf("Protocal:RARP\n");
	short temp=(p[0]<<8)+p[1];
	printf("format of heardware type:0x%02x\n",temp);

	p=p+2;
	temp=(p[0]<<8)+p[1];
	printf("format of protocol type:0x%04x\n",temp);

	p=p+2;
	temp=(p[0]);
	printf("length of hardware address:0x%d\n",temp);

	p=p+1;
	temp=(p[0]);
	printf("length of protocol address:0x%d\n",temp);

	p=p+1;
	temp=(p[0]<<8)+p[1];
	if(temp==0x1)
		printf("operation:RARP request\n");
	else 
		printf("operation:RARP responce\n");
	
	p=p+2;
	printf("sender MAC address:%.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=p+6;
	printf("sender IP address:%d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
	p=p+4;
	printf("target MAC address:%.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=p+6;
	printf("sender IP address:%d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);
}
