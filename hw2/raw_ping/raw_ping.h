/**************************************************
	> File Name:  raw_ping.h
	> Author:     Leuckart
	> Time:       2017-10-31 06:14
**************************************************/

#ifndef RAW_PING_H_
#define RAW_PING_H_

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#define IP_HDR_LEN sizeof(struct iphdr)
#define ICMP_HDR_LEN sizeof(struct icmphdr)
#define TV_LEN (sizeof(struct timeval))

#define ICMP_PACKET_LEN (ICMP_HDR_LEN+sizeof(struct timeval))
#define IP_PACKET_LEN (IP_HDR_LEN+ICMP_HDR_LEN+TV_LEN)

#define MAX_SIZE 1024

void Statistics(int num);

int InitSocket(const char *dst_ip);

void CloseSocket(int sockfd);

void IcmpRequest(int sockfd,int sequence);

void IcmpReply(int sockfd);

void FillIcmpHdr(int sequence);

unsigned short CheckSum(unsigned short *addr, int len);

#endif

