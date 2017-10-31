##################################################
# File Name:  Makefile
# Author:  Leuckart
# Time:    2017-10-31   18:18
##################################################

CC=gcc
CFLAGS=-g -Wall

all:ping socket

ping:./raw_ping/main.o ./raw_ping/raw_ping.o
	@$(CC) $(CFLAGS) -o ping ./raw_ping/main.o ./raw_ping/raw_ping.o
	@-rm ./raw_ping/*.o

./raw_ping/main.o:./raw_ping/main.c ./raw_ping/raw_ping.h
	@$(CC) $(CFLAGS) -c ./raw_ping/main.c -o ./raw_ping/main.o

./raw_ping/raw_ping.o:./raw_ping/raw_ping.c ./raw_ping/raw_ping.h
	@$(CC) $(CFLAGS) -c ./raw_ping/raw_ping.c -o ./raw_ping/raw_ping.o

socket:./raw_socket/main.o ./raw_socket/raw_socket.o
	@$(CC) $(CFLAGS) -o socket ./raw_socket/main.o ./raw_socket/raw_socket.o
	@-rm ./raw_socket/*.o

./raw_socket/main.o:./raw_socket/main.c ./raw_socket/raw_socket.h
	@$(CC) $(CFLAGS) -c ./raw_socket/main.c -o ./raw_socket/main.o

./raw_socket/raw_socket.o:./raw_socket/raw_socket.c ./raw_socket/raw_socket.h
	@$(CC) $(CFLAGS) -c ./raw_socket/raw_socket.c -o ./raw_socket/raw_socket.o

clean:
	-@rm ping socket
