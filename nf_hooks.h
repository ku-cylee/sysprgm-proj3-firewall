#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>

typedef struct {
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int protocol;
	char src_addr[128], dst_addr[128];
	unsigned short src_port, dst_port;
} PacketData;

static struct nf_hook_ops inbound_ops;
static struct nf_hook_ops outbound_ops;
static struct nf_hook_ops forward_ops;
static struct nf_hook_ops proxy_ops;
