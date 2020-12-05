#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

typedef struct rule {
	unsigned short port;
	char type;
	struct rule *next;
} Rule;

typedef struct {
	int size;
	Rule *head, *tail;
} RuleList;

RuleList *create_rule_list(void);
Rule *find_rule(RuleList *lst, unsigned short port, char type);
int insert_rule(RuleList *lst, unsigned short port, char type);
int remove_rule(RuleList *lst, int index);
ssize_t copy_rule(Rule **prule, char __user *user_buffer, int *index);
void destroy_rule_list(RuleList *lst);
