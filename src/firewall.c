#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define PROC_DIRNAME "group16"
#define ADD_FILENAME "add"
#define DEL_FILENAME "del"
#define SHOW_FILENAME "show"

#define INBOUND_TYPE  'I'
#define OUTBOUND_TYPE 'O'
#define FORWARD_TYPE  'F'
#define PROXY_TYPE    'P'

#define PROXY_DST_ADDR "131.1.1.1"
#define LOG_FORMAT     "%-15s:%2u,%5d,%5d,%-15s,%-15s\n"

#define BUFFER_SIZE 64

/////////////////// NETFILTER

static unsigned int inbound_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static unsigned int outbound_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static unsigned int forward_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

static unsigned int proxy_hook(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

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

/////////////////// RULES ADT

typedef struct rule {
	int port;
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

Rule *find_rule(RuleList *lst, int port, char type) {
	Rule *rule;
	for (rule = lst->head; rule != NULL && !(rule->port == port && rule->type == type); rule = rule->next);
	return rule;
}

int insert_rule(RuleList *lst, int port, char type) {
	Rule *rule;

	if (type != INBOUND_TYPE && type != OUTBOUND_TYPE && type != FORWARD_TYPE && type != PROXY_TYPE) return 0;
	if (find_rule(lst, port, type) != NULL) return 0;

	rule = (Rule *)kmalloc(sizeof(Rule), GFP_KERNEL);
	rule->port = port;
	rule->type = type;

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

ssize_t copy_rule(Rule **prule, char __user *user_buffer, int *index) {
	int len = sprintf(user_buffer, "%d(%c): %d\n", *index, (*prule)->type, (*prule)->port);
	(*index)++;
	return len;
}

/////////////////// KERNEL MODULE

static RuleList *rule_list;
static Rule *current_rule = NULL;
static int index = 0;

static struct proc_dir_entry *proc_dir, *add_file, *del_file, *show_file;

static int add_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "ADD OPEN\n");
	return 0;
}

static ssize_t add_write(struct file *file, const char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	int len = 0, port;
	char type, buffer[BUFFER_SIZE] = { 0 };

	if (copy_from_user(buffer, user_buf, count)) return 0;

	sscanf(buffer, "%c %d", &type, &port);
	len = strlen(buffer);
	insert_rule(rule_list, port, type);

	return len;
}

static const struct file_operations add_fops = {
	.owner = THIS_MODULE,
	.open = add_open,
	.write = add_write,
};

static int del_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "DEL OPEN\n");
	return 0;
}

static ssize_t del_write(struct file *file, const char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	int len = 0, index;
	char buffer[BUFFER_SIZE] = { 0 };

	if (copy_from_user(buffer, user_buf, count)) return 0;

	sscanf(buffer, "%d", &index);
	len = strlen(buffer);

	remove_rule(rule_list, index);
	return len;
}

static const struct file_operations del_fops = {
	.owner = THIS_MODULE,
	.open = del_open,
	.write = del_write,
};

static int show_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "SHOW OPEN\n");
	return 0;
}

static ssize_t show_read(struct file *file, char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	int len;

	if (index >= rule_list->size) {
		index = 0;
		return 0;
	}

	current_rule = (index == 0) ? rule_list->head : current_rule->next;
	len = copy_rule(&current_rule, user_buf, &index);
	return len;
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

	nf_register_hook(&inbound_ops);
	nf_register_hook(&outbound_ops);
	nf_register_hook(&forward_ops);
	nf_register_hook(&proxy_ops);
	return 0;
}

static void __exit firewall_exit(void) {
	remove_proc_entry(ADD_FILENAME, proc_dir);
	remove_proc_entry(DEL_FILENAME, proc_dir);
	remove_proc_entry(SHOW_FILENAME, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);

	nf_unregister_hook(&inbound_ops);
	nf_unregister_hook(&outbound_ops);
	nf_unregister_hook(&forward_ops);
	nf_unregister_hook(&proxy_ops);
	return;
}

module_init(firewall_init);
module_exit(firewall_exit);

MODULE_AUTHOR("ku-cylee, noparkee");
MODULE_DESCRIPTION("Custom Firewall for COSE322 System Programming Course");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
