#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "nf_hooks.h"
#include "rules_ADT.h"

#define PROC_DIRNAME "group16"
#define ADD_FILENAME "add"
#define DEL_FILENAME "del"
#define SHOW_FILENAME "show"

#define BUFFER_SIZE 64

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
	int len = 0;
	unsigned short port;
	char type, buffer[BUFFER_SIZE] = { 0 };

	if (copy_from_user(buffer, user_buf, count)) return 0;

	sscanf(buffer, "%c %hu", &type, &port);
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

	destroy_rule_list(rule_list);

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
