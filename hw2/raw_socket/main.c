/**************************************************
	> File Name:  main.c
	> Author:     Leuckart
	> Time:       2017-10-31 19:08
**************************************************/

#include "raw_socket.h"

int main(int argc,char* argv[])
{
	int sock_fd;
	char buffer[RECV_MAX];
	char *all_head;
	char *eth_type;

	if((sock_fd=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL)))<0)
	{
		printf("Socket Create Error\n");
		exit(1);
	}
	while(1)
	{
		if(recvfrom(sock_fd,buffer,RECV_MAX,0,NULL,NULL)<0)
		{
			printf("Recvfrom Error\n");
			exit(1);
		}
		struct ethhdr *eth_hd=(struct ethhdr *)buffer;

		printf("********************\n");
		printf("MAC address: %2x:%2x:%2x:%2x:%2x:%2x ==> %.2x:%02x:%02x:%02x:%02x:%02x\n",eth_hd->h_source[0],eth_hd->h_source[1],eth_hd->h_source[2],eth_hd->h_source[3],eth_hd->h_source[4],eth_hd->h_source[5],eth_hd->h_dest[0],eth_hd->h_dest[1],eth_hd->h_dest[2],eth_hd->h_dest[3],eth_hd->h_dest[4],eth_hd->h_dest[5]);

		all_head=buffer+14;
		eth_type=buffer+12;

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
			default:
				if(eth_type[1]==0x35)
				{
					RARP(all_head);
				}
				break;
		}
	}
	return 0;
}
