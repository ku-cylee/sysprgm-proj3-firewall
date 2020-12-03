#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#define PROC_DIRNAME "group16"
#define ADD_FILENAME "add"
#define DEL_FILENAME "del"
#define SHOW_FILENAME "show"

static struct proc_dir_entry *proc_dir, *add_file, *del_file, *show_file;

static int add_open(struct inode *inode, struct file *file) {
	printk(KERN_INFO "ADD OPEN\n");
	return 0;
}

static ssize_t add_write(struct file *file, const char __user *user_buf,
                                            size_t count, loff_t *ppos) {
	printk(KERN_INFO "ADD WRITE\n");
	return count;
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
    printk(KERN_INFO "DEL WRITE\n");
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
    printk(KERN_INFO "SHOW READ\n");
    return count;
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
