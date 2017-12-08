#ifndef DNSREWRITER_H
#define DNSREWRITER_H
#define REWRITE_Q 1
#define REWRITE_R 2
#include "hash.h"
#include "ntree_binary.h"


//int add_invert_resolution(hashtable *ht, char* tid, char* string, char* rewrited);
int move_rappel_bytes(struct pkt_buff *pbuff, dnspacket* p, char* new_str);
int set_checksum_to_zero(struct pkt_buff *pkb);
int replace_q(struct pkt_buff *pkb, dnspacket *packet, int nq, char* to_insert, uint8_t type);
int rewrite_dns(struct pkt_buff *sock_buff, unsigned char* labelized_query, hashtable* hashtable, dnspacket* packet, uint8_t type);








#endif
