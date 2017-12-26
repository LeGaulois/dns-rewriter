#ifndef DNSREWRITER_H
#define DNSREWRITER_H
#define REWRITE_Q 1
#define REWRITE_R 2
#include "hash.h"
#include "ntree_binary.h"


//int add_invert_resolution(hashtable *ht, char* tid, char* string, char* rewrited);
void move_all_rappel_bytes(dnspacket *p,char* new_str, int *bytes);
void move_rappel_bytes(dnspacket* p, char* new_str);
int set_checksum_to_zero(struct pkt_buff *pkb);
int udp_set_length(dnspacket *p);
int replace_query(dnspacket *packet, char* to_insert, uint8_t type);

int rewrite_dns_query(dnspacket* packet, unsigned char* query,
            hashtable* hashtable);
int rewrite_dns_response(dnspacket* packet, unsigned char* query,
            hashtable* hashtable);
int rewrite_dns(dnspacket* packet, unsigned char* query, 
        hashtable* hashtable, uint8_t type);


#endif
