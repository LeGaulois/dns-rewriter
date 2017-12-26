#ifndef DNSPARSER_H
#define DNSPARSER_H

#define UDP_HDR_SIZE 8
#define DNS_FIX_HDR_SIZE 12
/*
Structure contenant les informations principales 
sur les paquets DNS à traiter.

Certaines informations ne sont pas parsées car inutiles 
pour notre utilisation (c'est le cas du type de la requête etc)


Pour notre programme, on ne se soucie pas des réponses DNS.
*/
typedef struct _DNS_PACKET dnspacket;
typedef struct _DNS_QUERY dnsquery;
typedef struct _DNS_ANSWER dnsanswer;


struct _DNS_QUERY {
	unsigned int    length;
	unsigned char   *qname;
	unsigned char   qtype;
	unsigned char   qclass;
	unsigned char   *endquery;
};


struct _DNS_ANSWER {
    unsigned char   *name;       
    unsigned short int atype;
	unsigned short int   aclass;
	unsigned int    ttl;
	unsigned short int    datalen;
	unsigned char   *data;
};


/**
 * _DNS_PACKET
 * Structure représentant un paquet DNS
 * *@skb : pointeur sur le pkt_buff original
 * @user_data : pointeur sur le payload UDP, à savoir le
 * premier octet du message DNS
 * @transaction_id : ID de transaction DNS
 * @flags : Flags du message
 * @nb_XXXX : nombre d'éléments du paquets
 * @query : élement de type _DNS_QUERY, représentant la requête
 */

struct _DNS_PACKET {
	struct pkt_buff *skb;
	uint8_t         *user_data;
	uint8_t		    dns_len;
	
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
void set_dns_len(dnspacket *p);
int dnspacket_prepare_struct (dnspacket *p);
int dnspacket_parse_header(dnspacket *p);
int dnspacket_parse_query(dnspacket *p);
int dnspacket_parse(dnspacket *p);
dnsanswer parse_answer(dnspacket *p, int *p_actual, 
                int *tab_rappel_byte, int *nb_compress);
int* analyse_answer_for_rewrite_compression(dnspacket *p);

#endif
