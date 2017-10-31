#include "list.h"
#ifndef HASH_H
#define HASH_H
#define MAX_CASE_HASHTABLE 64


typedef struct dns_translation dns_t;

struct dns_translation {
	char* query;
	char* rewrited;
};


void do_hash(char *str, unsigned char *digest);
int get_val_from_digest(unsigned char *digest);
void gen_hash_table(list **hashtable);
void free_hashtable (list **hashtable);
dns_t* dns_struct_init();
dns_t* get_dns_by_query(list **hashtable, char* query);
int free_dnsdata(void *dnsdata);
int compare_dnsdata(void *dns1, void *dns2);

#endif



