#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PROC_DIRNAME   "group16"
#define ADD_FILENAME   "add"
#define DEL_FILENAME   "del"
#define SHOW_FILENAME  "show"

#define INBOUND_TYPE   'I'
#define OUTBOUND_TYPE  'O'
#define FORWARD_TYPE   'F'
#define PROXY_TYPE     'P'

#define SERVER_ADDR "192.168.56.101"
#define PROXY_DST_ADDR "131.1.1.1"
#define LOG_FORMAT     "%-15s:%2u,%5d,%5d,%-15s,%-15s,%d,%d,%d,%d\n"

#define BUFFER_SIZE    64

/////////////////// RULES ADT SECTION

typedef struct rule {
	unsigned short port;
	char type;
	struct rule *next;
} Rule;

typedef struct {
	int size;
	Rule *head, *tail;
} RuleList;

RuleList *create_rule_list(void) {
	RuleList *lst = (RuleList *)kmalloc(sizeof(RuleList), GFP_KERNEL);
	lst->size = 0;
	lst->head = NULL;
	lst->tail = NULL;
	return lst;
}

int find_rule(RuleList *lst, unsigned short port, char type) {
	Rule *rule;
	for (rule = lst->head;
	     rule != NULL && !(rule->port == port && rule->type == type);
	     rule = rule->next);
	return (rule != NULL);
}

int insert_rule(RuleList *lst, unsigned short port, char type) {
	Rule *rule;

	if (type != INBOUND_TYPE && type != OUTBOUND_TYPE &&
	    type != FORWARD_TYPE && type != PROXY_TYPE) return 0;
	if (find_rule(lst, port, type)) return 0;

	rule = (Rule *)kmalloc(sizeof(Rule), GFP_KERNEL);
	rule->port = port;
	rule->type = type;
	rule->next = NULL;

	if (lst->size == 0) lst->head = rule;
	else lst->tail->next = rule;

	lst->tail = rule;
	lst->size++;
	return 1;
}

int remove_rule(RuleList *lst, int index) {
	int i = 0;
	Rule *prev = NULL, *cur = lst->head;

	if (index < 0 || index >= lst->size) return 0;
	for (; i < index; i++, prev = cur, cur = cur->next);

	if (index == 0) lst->head = cur->next;
	else prev->next = cur->next;

	if (index + 1 == lst->size) lst->tail = prev;

	lst->size--;

	kfree(cur);
	return 1;
}

ssize_t copy_rule(RuleList *lst, Rule **prule, int *index, char __user *user_buffer) {
	*prule = (*index == 0) ? lst->head : (*prule)->next;
	sprintf(user_buffer, "%d(%c): %d\n", *index, (*prule)->type, (*prule)->port);
	(*index)++;
	return strlen(user_buffer);
}

void destroy_rule_list(RuleList *lst) {
	Rule *del_rule = NULL, *next_rule = NULL;
	for (del_rule = lst->head; del_rule != NULL; del_rule = next_rule) {
		next_rule = del_rule->next;
		kfree(next_rule);
	}
	kfree(lst);
}

/////////////////// GLOBAL VARIABLES SECTION

static RuleList *rule_list;
static Rule *current_rule = NULL;
static int rule_index = 0;

/////////////////// NETFILTER HOOKS SECTION

unsigned int addr_to_net(char *addr) {
	unsigned int i, net = 0, tmp[4];
	sscanf(addr, "%d.%d.%d.%d", &tmp[3], &tmp[2], &tmp[1], &tmp[0]);
	for (i = 0; i < 4; i++) {
		net <<= 8;
		net += tmp[i];
	}
	return net;
}

void net_to_addr(unsigned int net, char *addr) {
	unsigned int i, cmp = 255, tmp[4] = { 0 };
	for (i = 0; i < 4; i++) tmp[i] = (net >> (i * 8)) & cmp;
	sprintf(addr, "%u.%u.%u.%u", tmp[0], tmp[1], tmp[2], tmp[3]);
}

int is_server_addr(char *packet_addr) {
	unsigned short packet_addr_net = addr_to_net(packet_addr);
	unsigned short server_addr_net = addr_to_net(SERVER_ADDR);
	return packet_addr_net == server_addr_net;
}

typedef struct {
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	char src_addr[128], dst_addr[128];
	unsigned short src_port, dst_port;
} PacketData;

PacketData *parse_socket_buffer(struct sk_buff *skb) {
	PacketData *packet = (PacketData *)kmalloc(sizeof(PacketData), GFP_KERNEL);

	packet->ip_header = ip_hdr(skb);
	packet->tcp_header = tcp_hdr(skb);

	net_to_addr(packet->ip_header->saddr, packet->src_addr);
	net_to_addr(packet->ip_header->daddr, packet->dst_addr);

	packet->src_port = htons(packet->tcp_header->source);
	packet->dst_port = htons(packet->tcp_header->dest);

	return packet;
}

void print_log(PacketData *pkt, char *action_msg) {
	printk(KERN_NOTICE LOG_FORMAT,
	       action_msg, pkt->ip_header->protocol,
	       pkt->src_port, pkt->dst_port, pkt->src_addr, pkt->dst_addr,
	       pkt->tcp_header->syn, pkt->tcp_header->fin,
	       pkt->tcp_header->ack, pkt->tcp_header->rst);
}

static unsigned int prerouting_hook(void *priv,
                                    struct sk_buff *skb,
                                    const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	int is_server = is_server_addr(packet->src_addr);
	char *action_msg = "INBOUND";
	unsigned int next_action = NF_ACCEPT;

	if (is_server && find_rule(rule_list, packet->src_port, INBOUND_TYPE)) {
		action_msg = "DROP(INBOUND)";
		next_action = NF_DROP;
	} else if (find_rule(rule_list, packet->src_port, PROXY_TYPE)) {
		action_msg = "PROXY(INBOUND)";
		packet->ip_header->daddr = addr_to_net(PROXY_DST_ADDR);
		packet->tcp_header->dest = packet->tcp_header->source;
	}

	print_log(packet, action_msg);
	kfree(packet);
	return next_action;
}

static unsigned int postrouting_hook(void *priv,
                                     struct sk_buff *skb,
                                     const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	int is_server = is_server_addr(packet->dst_addr);
	int is_drop = is_server && find_rule(rule_list, packet->dst_port, OUTBOUND_TYPE);
	char *action_msg = is_drop ? "DROP(OUTBOUND)" : "OUTBOUND";
	unsigned int next_action = is_drop ? NF_DROP : NF_ACCEPT;

	print_log(packet, action_msg);
	kfree(packet);
	return next_action;
}

static unsigned int forward_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state) {
	PacketData *packet = parse_socket_buffer(skb);
	int is_server = is_server_addr(packet->src_addr);
	int is_drop = is_server && find_rule(rule_list, packet->dst_port, FORWARD_TYPE);
	char *action_msg = is_drop ? "DROP(FORWARD)" : "FORWARD";
	unsigned int next_action = is_drop ? NF_DROP : NF_ACCEPT;

	print_log(packet, action_msg);
	kfree(packet);
	return next_action;
}

static struct nf_hook_ops prerouting_ops = {
	.hook = prerouting_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops postrouting_ops = {
	.hook = postrouting_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops forward_ops = {
	.hook = forward_hook,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST,
};

/////////////////// KERNEL MODULE

static struct proc_dir_entry *proc_dir, *add_file, *del_file, *show_file;

static int add_open(struct inode *inode, struct file *file) {
	return 0;
}

static ssize_t add_write(struct file *file, const char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	unsigned short port;
	char type, buffer[BUFFER_SIZE] = { 0 };

	if (copy_from_user(buffer, user_buf, count)) return 0;

	sscanf(buffer, "%c %hu", &type, &port);
	insert_rule(rule_list, port, type);

	return strlen(buffer);
}

static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = add_open,
	.write = add_write,
};

static int del_open(struct inode *inode, struct file *file) {
	return 0;
}

static ssize_t del_write(struct file *file, const char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	int index;
	char buffer[BUFFER_SIZE] = { 0 };

	if (copy_from_user(buffer, user_buf, count)) return 0;

	sscanf(buffer, "%d", &index);
	remove_rule(rule_list, index);
	return strlen(buffer);
}

static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = del_open,
	.write = del_write,
};

static int show_open(struct inode *inode, struct file *file) {
	return 0;
}

static ssize_t show_read(struct file *file, char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	if (rule_index >= rule_list->size) {
		rule_index = 0;
		return 0;
	}
	return copy_rule(rule_list, &current_rule, &rule_index, user_buf);
}

static const struct file_operations show_fops = {
	.owner = THIS_MODULE,
	.open = show_open,
	.read = show_read,
};


static int __init firewall_init(void) {
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	add_file = proc_create(ADD_FILENAME, 0777, proc_dir, &add_fops);
	del_file = proc_create(DEL_FILENAME, 0777, proc_dir, &del_fops);
	show_file = proc_create(SHOW_FILENAME, 0777, proc_dir, &show_fops);

	rule_list = create_rule_list();

	nf_register_hook(&prerouting_ops);
	nf_register_hook(&postrouting_ops);
	nf_register_hook(&forward_ops);
	return 0;
}

static void __exit firewall_exit(void) {
	remove_proc_entry(ADD_FILENAME, proc_dir);
	remove_proc_entry(DEL_FILENAME, proc_dir);
	remove_proc_entry(SHOW_FILENAME, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);

	destroy_rule_list(rule_list);

	nf_unregister_hook(&prerouting_ops);
	nf_unregister_hook(&postrouting_ops);
	nf_unregister_hook(&forward_ops);
	return;
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_AUTHOR("ku-cylee, noparkee");
MODULE_DESCRIPTION("Custom Firewall for COSE322 System Programming Course");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
