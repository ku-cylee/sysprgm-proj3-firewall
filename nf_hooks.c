#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include "rules_ADT.h"

#define INBOUND_TYPE  'I'
#define OUTBOUND_TYPE 'O'
#define FORWARD_TYPE  'F'
#define PROXY_TYPE    'P'

#define PROXY_DST_ADDR "131.1.1.1"
#define LOG_FORMAT     "%-15s:%2u,%5d,%5d,%-15s,%-15s\n"

#define BUFFER_SIZE 64

unsigned int addr_to_net(char *addr) {
	unsigned int arr[4];
	sscanf(addr, "%d.%d.%d.%d", &arr[0], &arr[1], &arr[2], &arr[3]);
	return *(unsigned int *)arr;
}

void net_to_addr(unsigned int net, char *addr) {
	unsigned char *tmp = (unsigned char *)&net;
	sprintf(addr, "%u.%u.%u.%u", tmp[0], tmp[1], tmp[2], tmp[3]);
}

typedef struct {
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	int protocol;
	char src_addr[128], dst_addr[128];
	unsigned short src_port, dst_port;
} PacketData;

PacketData *parse_socket_buffer(struct sk_buff *skb) {
	PacketData *packet = (PacketData *)kmalloc(sizeof(PacketData), GFP_KERNEL);

	packet->ip_header = ip_hdr(skb);
	packet->tcp_header = tcp_hdr(skb);

	net_to_addr((unsigned int)packet->ip_header->saddr, packet->src_addr);
	net_to_addr((unsigned int)packet->ip_header->daddr, packet->dst_addr);

	packet->src_port = htons(packet->tcp_header->source);
	packet->dst_port = htons(packet->tcp_header->dest);

	packet->protocol = packet->ip_header->protocol;

	return packet;
}

void print_log(PacketData *pkt, char *rule_type) {
	printk(KERN_NOTICE LOG_FORMAT,
	       rule_type, pkt->protocol,
	       pkt->src_port, pkt->dst_port, pkt->src_addr, pkt->dst_addr);
}

static unsigned int inbound_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	Rule *rule = find_rule(rule_list, packet->src_port, INBOUND_TYPE);

	if (rule == NULL) {
		print_log(packet, "INBOUND");
		kfree(packet);
		return NF_ACCEPT;
	} else {
		print_log(packet, "DROP(INBOUND)");
		kfree(packet);
		return NF_DROP;
	}
}

static unsigned int outbound_hook(void *priv,
                                  struct sk_buff *skb,
                                  const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	Rule *rule = find_rule(rule_list, packet->dst_port, OUTBOUND_TYPE);

	if (rule == NULL) {
		print_log(packet, "OUTBOUND");
		kfree(packet);
		return NF_ACCEPT;
	} else {
		print_log(packet, "DROP(OUTBOUND)");
		kfree(packet);
		return NF_DROP;
	}
}

static unsigned int forward_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	Rule *rule = find_rule(rule_list, packet->dst_port, FORWARD_TYPE);

	if (rule == NULL) {
		print_log(packet, "FORWARD");
		kfree(packet);
		return NF_ACCEPT;
	} else {
		print_log(packet, "DROP(FORWARD)");
		kfree(packet);
		return NF_DROP;
	}
}

static unsigned int proxy_hook(void *priv,
                               struct sk_buff *skb,
                               const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	Rule *rule = find_rule(rule_list, packet->src_port, PROXY_TYPE);

	if (rule != NULL) {
		packet->tcp_header->dest = packet->tcp_header->source;
		print_log(packet, "PROXY(INBOUND)");
	}

	kfree(packet);
	return NF_ACCEPT;
}

static struct nf_hook_ops inbound_ops = {
	.hook = inbound_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = 1,
};

static struct nf_hook_ops outbound_ops = {
	.hook = outbound_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = 1,
};

static struct nf_hook_ops forward_ops = {
	.hook = forward_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = 1,
};

static struct nf_hook_ops proxy_ops = {
	.hook = proxy_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = 1,
};
