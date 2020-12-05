#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include "rules_ADT.h"

#define INBOUND_TYPE  'I'
#define OUTBOUND_TYPE 'O'
#define FORWARD_TYPE  'F'
#define PROXY_TYPE    'P'

RuleList *create_rule_list(void) {
	RuleList *lst = (RuleList *)kmalloc(sizeof(RuleList), GFP_KERNEL);
	lst->size = 0;
	lst->head = NULL;
	lst->tail = NULL;
	return lst;
}

Rule *find_rule(RuleList *lst, unsigned short port, char type) {
	Rule *rule;
	for (rule = lst->head; rule != NULL && !(rule->port == port && rule->type == type); rule = rule->next);
	return rule;
}

int insert_rule(RuleList *lst, unsigned short port, char type) {
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

void destroy_rule_list(RuleList *lst) {
	Rule *del_rule = NULL, *next_rule = NULL;
	for (del_rule = lst->head; del_rule != NULL; del_rule = next_rule) {
		next_rule = del_rule->next;
		kfree(next_rule);
	}
	kfree(lst);
}
