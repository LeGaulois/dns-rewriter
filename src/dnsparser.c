#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <netinet/in.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <libnetfilter_queue/pktbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "dnsparser.h"
#include "workers.h"
#include "logger.h"


extern worker *ME;



/**
 * INIT_STRUCT_DNSPACKET
 * Initie une structure dnspacket.
 */
dnspacket* init_struct_dnspacket() 
{
	dnspacket *p = NULL;
	p = calloc(1,sizeof(dnspacket));
	
	if(!p){
	    return NULL;
	}
	
	p->skb              = NULL;
	p->user_data        = NULL;
    p->transaction_id 	= calloc(8,sizeof(char));
    p->flags 		    = 0;
	p->nb_queries       = 0;
	p->nb_replies       = 0;
	p->nb_author_reply	= 0;
	p->nb_add_reply 	= 0;
	p->nb_q_rewrited	= 0;
	p->query.length     = 0;
    p->query.qname      = calloc(253, sizeof(char));
    p->query.qtype      = 0;
    p->query.qclass     = 0;
	
	return p;	
}


/**
 * DESTROY_DNSPACKET
 * Détruit une structure dnspacket
 */
void destroy_dnspacket(dnspacket* dnsp) {
    pktb_free(dnsp->skb);
    free(dnsp->transaction_id);
	free(dnsp->query.qname);
	free(dnsp);
}


/**
 * DNSPACKET_PREPARE_STRUCT
 * Vérifie les caractéristiques du paquet IP reçu.
 * Récupère le payload.
 *
 * Valeurs de retour:
 *  0 -> SUCCESS
 * -1 -> ERROR
 */
int dnspacket_prepare_struct(dnspacket *p)
{
	struct iphdr *iph   = NULL;
	struct udphdr *udph = NULL;
	
	if(!p){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
La structure dnspacket recu est NULL.",ME->number);
        return -1;
	}
	
	if(!(p->skb)){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
La structure dnspacket recu ne possede pas de skbuff.",ME->number);
        return -1;
	}
	
	iph = (struct iphdr *)nfq_ip_get_hdr(p->skb);
	
	nfq_ip_set_transport_header(p->skb, iph);
	udph = (struct udphdr *)nfq_udp_get_hdr(p->skb);
	
	if(!iph){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Impossible de récupérer l'entête IP.",ME->number);
	    return -1;
	}

	if(!udph){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Impossible de récupérer l'entête UDP.",ME->number);
	    return -1;
	}

	if( (iph->protocol != IPPROTO_UDP) && (udph->dest != 53 )){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Le paquet reçu n'est pas une transaction DNS.",ME->number);
	    return -1;
	}
	
	p->user_data = pktb_transport_header(p->skb) + UDP_HDR_SIZE;
	
	if(!p->user_data){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Le paquet reçu n'a pas de donnée utile.",ME->number);
	    return -1;
	}
	
	return 0;
}	


/**
 * DNSPACKET_PARSE_HEADER
 * Parse l'entête DNS (partie fixe de la requête).
 *
 * Valeurs de retour:
 *  0 -> SUCCESS
 *  1 -> ERROR
 */
int dnspacket_parse_header(dnspacket *p)
{
    if (!p){
        SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
La structure dnspacket recu est NULL.",ME->number);
        return 1;
    }
    
	sprintf((char *__restrict__)(p->transaction_id),"%02x%02x",p->user_data[0],p->user_data[1]);
	p->flags		= ((uint16_t)p->user_data[2]<<8) 
	                    + (uint16_t)p->user_data[3];
	p->nb_queries		= (int)*(p->user_data+4)+(int)*(p->user_data+5);	                
	p->nb_replies		= (int)*(p->user_data+6) + (int)*(p->user_data+7);
	p->nb_author_reply	= (int)*(p->user_data+8) + (int)*(p->user_data+9);
	p->nb_add_reply		= (int)*(p->user_data+10) + (int)*(p->user_data+11);
	
	return 0;
}
	

/**
 * DNSPACKET_PARSE_HEADER
 * Parse l'entête DNS (partie fixe de la requête).
 *
 * Valeurs de retour:
 *  0 -> SUCCESS
 *  1 -> ERROR
 */
int dnspacket_parse_query(dnspacket *p)
{
    unsigned char *pinit = NULL;
	int i=0, nb_char=0, size_char = 0;
	
   /** 
    * Si la trame est une réponse DNS 
    * mais ne contient pas de champ ANSWER, on drop. 
    * Trop compliqué à parser et non pertinent
    */	
	if((p->flags == 0x8180 || p->flags == 0x8580) && p->nb_replies == 0){
	   SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
La trame DNS ne sera pas traité (flags_answer = 1) \
mais pas de réponse.",ME->number);
	    return -1;
	}
	
    /**
     * Conversion des requetes en string & remplissage des structures 
	 */
	pinit = p->user_data + DNS_FIX_HDR_SIZE;

	while(*(pinit+size_char) != 0x00 && size_char < 253) {
		nb_char = (int)*(pinit+size_char);
		
		for(i=0;i<nb_char;i++){
			p->query.qname[size_char] = (unsigned char) *(pinit + size_char + 1); 
			size_char++;
		}
		p->query.qname[size_char] = '.';
		size_char++;
	}
	
	p->query.qname[size_char]	= '\0';
	p->query.length	            = size_char;
	p->query.qtype	            = *(pinit + size_char + 2);
	p->query.qclass	            = *(pinit + size_char + 4);
	
	SLOGL_vprint(SLOGL_LVL_DEBUG,"[worker %d] \
Réception de la requete DNS: QTYPE=%d QCLASS=%d QUERY=%s",
ME->number, p->query.qtype, p->query.qclass, p->query.qname);

	return 0;
}


/**
 * DNSPACKET_PARSE
 * Fonction permettant de parser un skbuff 
 * qui servira à compléter la structure dnspacket
 */
int dnspacket_parse(dnspacket *p){
    if ( dnspacket_prepare_struct(p) != 0) goto error;
    if ( dnspacket_parse_header(p) != 0) goto error;
    if ( dnspacket_parse_query(p) != 0) goto error;
    return 0;
    
    error:
        return -1;
}
