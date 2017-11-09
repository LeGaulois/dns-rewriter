#ifndef DNS_TRANSLATION_H
#define DNS_TRANSLATION_H


typedef struct dns_translation dns_t;

struct dns_translation {
	char* query;
	char* rewrited;
};

dns_t* dns_translation_init();
int dns_translation_free(void **dns);
int dns_translation_compare_struct(void *dns1, void *dns2);
int dns_translation_compare_query(void *strquery, void *dns1);
#endif
