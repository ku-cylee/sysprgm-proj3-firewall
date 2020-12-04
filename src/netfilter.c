#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PROC_DIRNAME "group16"
#define ADD_FILENAME "add"
#define DEL_FILENAME "del"
#define SHOW_FILENAME "show"

#define INBOUND_TYPE  'I'
#define OUTBOUND_TYPE 'O'
#define FORWARD_TYPE  'F'
#define PROXY_TYPE    'P'

#define BUFFER_SIZE 64

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

RuleList *createRuleList(void) {
	RuleList *lst = (RuleList *)kmalloc(sizeof(RuleList), GFP_KERNEL);
	lst->size = 0;
	lst->head = NULL;
	lst->tail = NULL;
	return lst;
}

Rule *findRule(RuleList *lst, int port, char type) {
	Rule *rule;
	for (rule = lst->head; rule != NULL && !(rule->port == port && rule->type == type); rule = rule->next);
	return rule;
}

int insertRule(RuleList *lst, int port, char type) {
	if (type != INBOUND_TYPE && type != OUTBOUND_TYPE && type != FORWARD_TYPE && type != PROXY_TYPE) return 0;
	if (findRule(lst, port, type) != NULL) return 0;

	Rule *rule = (Rule *)kmalloc(sizeof(Rule), GFP_KERNEL);
	rule->port = port;
	rule->type = type;

	if (lst->size == 0) lst->head = rule;
	else lst->tail->next = rule;

	lst->tail = rule;
	lst->size++;
	return 1;
}

int removeRule(RuleList *lst, int index) {
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

ssize_t copyRule(Rule **rulePtr, char __user *user_buffer, int *index) {
	int len = sprintf(user_buffer, "%d(%c): %d\n", *index, (*rulePtr)->type, (*rulePtr)->port);
	(*index)++;
	return len;
}

/////////////////// KERNEL MODULE

static RuleList *ruleList;
static Rule *currentRule = NULL;
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
	insertRule(ruleList, port, type);

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

	removeRule(ruleList, index);
    return count;
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
    if (index >= ruleList->size) {
		index = 0;
		return 0;
	}

	if (index == 0) currentRule = ruleList->head;
	else currentRule = currentRule->next;

	int len = copyRule(&currentRule, user_buf, &index);
	return len;
}

static const struct file_operations show_fops = {
    .owner = THIS_MODULE,
    .open = show_open,
    .read = show_read,
};


static int __init netfilter_init(void) {
	proc_dir = proc_mkdir(PROC_DIRNAME, NULL);
	add_file = proc_create(ADD_FILENAME, 0777, proc_dir, &add_fops);
	del_file = proc_create(DEL_FILENAME, 0777, proc_dir, &del_fops);
	show_file = proc_create(SHOW_FILENAME, 0777, proc_dir, &show_fops);

	ruleList = createRuleList();
	return 0;
}

static void __exit netfilter_exit(void) {
	remove_proc_entry(ADD_FILENAME, proc_dir);
	remove_proc_entry(DEL_FILENAME, proc_dir);
	remove_proc_entry(SHOW_FILENAME, proc_dir);
	remove_proc_entry(PROC_DIRNAME, NULL);
	return;
}

module_init(netfilter_init);
module_exit(netfilter_exit);

MODULE_AUTHOR("ku-cylee, noparkee");
MODULE_DESCRIPTION("Custom Netfilter for COSE322 System Programming Course");
MODULE_LICENSE("GPL");
MODULE_VERSION("NEW");
