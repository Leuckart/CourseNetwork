/**************************************************
	> File Name:  main.h
	> Author:     Leuckart
	> Time:       2017-10-31 06:14
**************************************************/

#include "raw_ping.h"

int main(int argc,char* argv[])
{
	signal(SIGINT,Statistics);
	int socket_fd=InitSocket(argv[argc-1]);

	for(int seq=1;;++seq)
	{
		IcmpRequest(socket_fd,seq);
		IcmpReply(socket_fd);
		sleep(1);
	}

	CloseSocket(socket_fd);
	return 0;
}
