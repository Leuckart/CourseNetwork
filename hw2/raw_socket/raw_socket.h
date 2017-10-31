/**************************************************
	> File Name:  raw_socket.h
	> Author:     Leuckart
	> Time:       2017-10-31 19:08
**************************************************/

#ifndef RAW_SOCKET_H_
#define RAW_SOCKET_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/if_ether.h>

#define RECV_MAX 1024
#define SEND_HARD_ADDR (3*sizeof(unsigned short)+2*sizeof(unsigned char))
#define SEND_PROTO_ADDR (SEND_HARD_ADDR+6*sizeof(unsigned char))
#define TARG_HARD_ADDR (SEND_PROTO_ADDR+sizeof(__be32))
#define TARG_PROTO_ADDR (TARG_HARD_ADDR+6*sizeof(unsigned char))

struct arphdr
{
	unsigned short arp_hrd;    /* format of hardware address *///
	unsigned short arp_pro;    /* format of protocol address */
	unsigned char arp_hln;    /* length of hardware address */
	unsigned char arp_pln;    /* length of protocol address */
	unsigned short arp_op;     /* ARP/RARP operation */

	unsigned char arp_sha[6];    /* sender hardware address */
	__be32 arp_spa;    /* sender protocol address */   //FXCK
	unsigned char arp_tha[6];    /* target hardware address */
	__be32 arp_tpa;    /* target protocol address */
};

struct rarphdr
{
	unsigned short rarp_hrd;    /* format of hardware address */
	unsigned short rarp_pro;    /* format of protocol address */
	unsigned char rarp_hln;    /* length of hardware address */
	unsigned char rarp_pln;    /* length of protocol address */
	unsigned short rarp_op;     /* ARP/RARP operation */

	unsigned char rarp_sha[6];    /* sender hardware address */
	__be32 rarp_spa;    /* sender protocol address */
	unsigned char rarp_tha[6];    /* target hardware address */
	__be32 rarp_tpa;    /* target protocol address */
};

struct IPAddress
{
	int a;
	int b;
	int c;
	int d;
};

void IP(char *ip);

void ARP(char *arp);

void RARP(char *rarp);

#endif

