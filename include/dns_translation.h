#ifndef DNS_TRANSLATION_H
#define DNS_TRANSLATION_H

#include "hash.h"
#include <stdint.h>


typedef struct dns_translation dns_t;

struct dns_translation {
	char* query;
	char* rewrited;
};

dns_t* dns_translation_init();
int dns_translation_free(void **dns);
int dns_translation_compare_struct(void *dns1, void *dns2);
int dns_translation_compare_query(void *strquery, void *dns1);
int hashtable_complete_from_file(hashtable *ht, char *file, uint8_t type);
int hashtable_add_entry_from_line(hashtable *ht, char line[],uint8_t type);
void read_dnspopfile(int fd, hashtable *ht, uint8_t type);

#endif 
