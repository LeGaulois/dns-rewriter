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
	unsigned int    length;
	unsigned char   *qname;
	unsigned char   qtype;
	unsigned char   qclass;
};

struct _DNS_PACKET {
	struct pkt_buff *skb;
	uint8_t         *user_data;
	
	unsigned char   *transaction_id;
	uint16_t        flags;
	unsigned int    nb_queries;
	unsigned int    nb_replies;
	unsigned int    nb_author_reply;
	unsigned int    nb_add_reply;
	unsigned int    nb_q_rewrited;

	dnsquery        query;
};


dnspacket* init_struct_dnspacket();
void destroy_dnspacket(dnspacket* dnsp);
int dnspacket_prepare_struct (dnspacket *p);
int dnspacket_parse_header(dnspacket *p);
int dnspacket_parse_query(dnspacket *p);
int dnspacket_parse(dnspacket *p);

#endif
