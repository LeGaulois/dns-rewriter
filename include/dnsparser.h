#ifndef DNSPARSER_H
#define DNSPARSER_H

#define UDP_HDR_SIZE 8
#define DNS_FIX_HDR_SIZE 12
/*
Structure contenant les informations principales 
sur les paquets DNS à traiter.

Certaines informations ne sont pas parsées car inutiles 
pour notre utilisation (c'est le cas du type de la requête etc)

On utilisera pour stocker les requêtes multiples un 
tableau de structures.
Exemple :  sur des querys :  si 3 queries, 
queries[0/1/2] pointeront chacun sur une structure DNS_QUERY 
qui contiendront un attribut qname.

Pour notre programme, on ne se soucie pas des réponses DNS.
*/
typedef struct _DNS_PACKET dnspacket;
typedef struct _DNS_QUERY dnsquery;


struct _DNS_QUERY {
	unsigned int length;
	unsigned char* qname;
	unsigned char qtype;
	unsigned char qclass;
};

struct _DNS_PACKET {
	struct pkt_buff* skb;
	unsigned char* transaction_id;
	uint16_t flags;
	unsigned int nb_queries;
	unsigned int nb_replies;
	unsigned int nb_author_reply;
	unsigned int nb_add_reply;
	unsigned int nb_q_rewrited;
	
	unsigned char **pos_query_in_frame;
	dnsquery *queries;
};
int get_nb_dnsquery(struct pkt_buff *pbuff);
void init_dns_query(dnsquery* d);
dnspacket* init_struct_dnspacket(int nb_queries);
void destroy_dnsquery(dnsquery* d);
void destroy_dnspacket(dnspacket* d);
int dns_req_parsing (struct pkt_buff *sock_buffer, dnspacket *p,int nbq);
void affiche_queries(dnspacket *p);

#endif
