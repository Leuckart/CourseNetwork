/**************************************************
	> File Name:  raw_socket.c
	> Author:     Leuckart
	> Time:       2017-10-17 14:55
**************************************************/

#include "raw_socket.h"

struct IPAddress GetAddress(__be32 num)
{
	struct IPAddress addr;
	addr.a=num%256;
	num/=256;
	addr.b=num%256;
	num/=256;
	addr.c=num%256;
	num/=256;
	addr.d=num%256;
	return addr;
}

void IP(char *ip)
{
	struct iphdr *header=(struct iphdr *)(ip);
	struct IPAddress srcIP=GetAddress(header->saddr);
	struct IPAddress destIP=GetAddress(header->daddr);
	printf("********************\n");
	printf("IP1:%d.%d.%d.%d ==> %d.%d.%d.%d\n",srcIP.a,srcIP.b,srcIP.c,srcIP.d,destIP.a,destIP.b,destIP.c,destIP.d);
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
			printf("ipv6\n");
			break;
		case IPPROTO_RSVP:/* RSVP Protocol			*/
			printf("rsvp\n");
			break;
		case IPPROTO_GRE:/* Cisco GRE tunnels (rfc 1701,1702)	*/
			printf("gre\n");
			break;
		case IPPROTO_ESP:/* Encapsulation Security Payload protocol */
			printf("esp\n");
			break;
		case IPPROTO_AH:/* Authentication Header protocol	*/
			printf("ah\n");
			break;
		case IPPROTO_MTP:/* Multicast Transport Protocol		*/
			printf("mtp\n");
			break;
		case IPPROTO_BEETPH:/* IP option pseudo header for BEET	*/
			printf("beetph\n");
			break;
		case IPPROTO_ENCAP:/* Encapsulation Header			*/
			printf("encap\n");
			break;
		case IPPROTO_PIM:/* Protocol Independent Multicast	*/
			printf("pim\n");
			break;
		case IPPROTO_COMP:/* Compression Header Protocol		*/
			printf("comp\n");
			break;
		case IPPROTO_SCTP:/* Stream Control Transport Protocol	*/
			printf("sctp\n");
			break;
		case IPPROTO_UDPLITE:/* UDP-Lite (RFC 3828)			*/
			printf("udplite\n");
			break;
		case IPPROTO_MPLS:/* MPLS in IP (RFC 4023)		*/
			printf("mpls\n");
			break;
		case IPPROTO_RAW:/* Raw IP packets			*/
			printf("raw\n");
			break;
		default:
			printf("please query yourself\n");
	}
	printf("Header Length:%d\n",header->ihl);
	printf("Version:%d\n",header->version);
	printf("tos:%d\n",header->tos);
	printf("Total Length:%d\n",header->tot_len);
	printf("ID:%d\n",header->id);
	printf("fragment off:%d\n",header->frag_off);
	printf("TTL:%d\n",header->ttl);
	printf("********************\n\n");
}

void ARP(char *arp)
{
	printf("********************\n");
	struct arphdr *header=(struct arphdr *)(arp);
	unsigned char *p;

	printf("Protocal:ARP\n");
	printf("Format of hardware Type address:0x%02x\n",htons(header->arp_hrd));
	printf("Format of protocol address:0x%02x\n",htons(header->arp_pro));
	printf("Length of hardware address:0x%d\n",header->arp_hln);
	printf("Length of protocol address:0x%d\n",header->arp_pln);
	printf("%s\n",htons(header->arp_op)==0x0001?("ARP opcode (command): Request"):(htons(header->arp_op)==0x0002?("ARP opcode (command): Reply"):("Else")));

	p=(unsigned char *)header+SEND_HARD_ADDR;
	printf("Sender hardware address: %.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=(unsigned char *)header+SEND_PROTO_ADDR;
	printf("Sender protocol address: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);

	p=(unsigned char *)header+TARG_HARD_ADDR;
	printf("Target hardware address: %.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=(unsigned char *)header+TARG_PROTO_ADDR;
	printf("Target IP address: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);

	printf("********************\n\n");
}

void RARP(char *rarp)
{
	printf("********************\n");
	struct rarphdr *header=(struct rarphdr *)(rarp);
	unsigned char *p;

	printf("Protocal:RARP\n");
	printf("Format of hardware Type address:0x%02x\n",htons(header->rarp_hrd));
	printf("Format of protocol address:0x%04x\n",htons(header->rarp_pro));
	printf("Length of hardware address:0x%d\n",header->rarp_hln);
	printf("Length of protocol address:0x%d\n",header->rarp_pln);
	printf("%s\n",htons(header->rarp_op)==0x0003?("RARP opcode (command): Request"):(htons(header->rarp_op)==0x0004?("RARP opcode (command): Reply"):("Else")));

	p=(unsigned char *)header+SEND_HARD_ADDR;
	printf("Sender hardware address: %.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=(unsigned char *)header+SEND_PROTO_ADDR;
	printf("Sender protocol address: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);

	p=(unsigned char *)header+TARG_HARD_ADDR;
	printf("Target hardware address: %.2x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
	p=(unsigned char *)header+TARG_PROTO_ADDR;
	printf("Target IP address: %d.%d.%d.%d\n",p[0],p[1],p[2],p[3]);

	printf("********************\n\n");
}
