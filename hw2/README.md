# CourseNetwork

struct timeval
{
	__time_t tv_sec;
	__suseconds_t tv_usec;
};
#define __SOCK_SIZE__ 16
struct sockaddr_in
{
	__kernel_sa_family_t sin_family;
	__be16 sin_port;
	struct in_addr	sin_addr;
	unsigned char __pad[__SOCK_SIZE__-sizeof(short int)-sizeof(unsigned short int)-sizeof(struct in_addr)];
};

typedef uint32_t in_addr_t;
struct in_addr
{
	in_addr_t s_addr;
};

struct icmphdr {
  __u8		type;
  __u8		code;
  __sum16	checksum;
  union {
	struct {
		__be16	id;
		__be16	sequence;
	} echo;
	__be32	gateway;
	struct {
		__be16	__unused;
		__be16	mtu;
	} frag;
	__u8	reserved[4];
  } un;
};
