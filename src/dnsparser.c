#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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

int get_nb_dnsquery(struct pkt_buff *pbuff) {

	struct iphdr *ip = nfq_ip_get_hdr(pbuff);
	nfq_ip_set_transport_header(pbuff, ip);
	
	uint8_t *user_data = NULL;
	user_data = pktb_transport_header(pbuff) + 8;
	if(user_data == NULL) return -10;
	return user_data[5];
}
void init_dns_query(dnsquery* d) {
	if(d != NULL) {
		d->length	= 0;
		d->qtype	= 0;
		d->qclass	= 0;
		d->qname	= NULL;
		d->qname	= calloc(253,sizeof(char));
	}
}
dnspacket* init_struct_dnspacket(int nb_queries) {
	dnspacket *p = NULL;
	p = calloc(1,sizeof(dnspacket));
	
	if(p != NULL) {
		p->queries = NULL;
	
		p->queries = calloc(nb_queries,sizeof(dnsquery));
	
		for(int i=0;i<nb_queries;i++) {
			init_dns_query(p->queries + i);
		}

		p->pos_query_in_frame = calloc(nb_queries,sizeof(unsigned char*));

		p->nb_queries = nb_queries;
		p->nb_replies = 0;
		
		p->transaction_id 	= calloc(8,sizeof(char));
		p->flags 		= 0;
		p->nb_author_reply	= 0;
		p->nb_add_reply 	= 0;
		return p;	
	}
	else return NULL;
}
void destroy_dnsquery(dnsquery* d) {
	free(d->qname);
	free(d);
}

void destroy_dnspacket(dnspacket* d) {
	for(int i=0;i<d->nb_queries;i++) {
		destroy_dnsquery(&d->queries[i]);
	}
	free(d->queries);
	free(d);
}


/* FONCTION DE PARSING - 1ERES VERIFICATIONS SUR LES PAQUETS

Retourne -1 en cas d'erreur : UDP & DNS MANDATORY & QUERY/RESP MANDATORY 
A FAIRE EN CAS DE -1 : NF_ACCEPT sans traitement

*/


int dns_req_parsing (struct pkt_buff *sock_buffer, struct _DNS_PACKET *p, int nbq) {
	
/* DECLARATION DES PREMIERES VARIABLES */
	struct iphdr *iph;
	struct udphdr *udph;
	
	//pointers to the first byte of the IP/TRANSPORT HEADER.
	iph = (struct iphdr *)nfq_ip_get_hdr(sock_buffer);
	udph = (struct udphdr *)nfq_udp_get_hdr(sock_buffer);
	
/* VERIFICATION USUELLES */
	if(iph->protocol != IPPROTO_UDP && udph->dest != 53 ) return -1;
	
	nfq_ip_set_transport_header(sock_buffer, iph);
	//pointer to user_data
	uint8_t *user_data = NULL;
	user_data = pktb_transport_header(sock_buffer) + UDP_HDR_SIZE;
	if(user_data == NULL) return -2;
	
	if(p == NULL) return -3;
	
	char test[3];
	p->skb 			= sock_buffer;
	fprintf(stderr,"TID : %02x - %02x\n\n",user_data[0],user_data[1]);
	sprintf(p->transaction_id,"%02x%02x",user_data[0],user_data[1]);
	p->flags		= ((uint16_t)user_data[2]<<8) + (uint16_t)user_data[3];
	p->nb_replies		= user_data[7];
	p->nb_author_reply	= (int)*(user_data+8) + (int)*(user_data+9);
	p->nb_add_reply		= (int)*(user_data+10) + (int)*(user_data+11);
	p->nb_q_rewrited	= 0;

	
	
/* Si la trame est une réponse DNS mais ne contient pas de champ ANSWER, on drop. 
Trop compliqué à parser et non pertinent
*/	
	if((p->flags == 0x8180 || p->flags == 0x8580) && p->nb_replies == 0) return -4;
	
/* Conversion des requetes en string & remplissage des structures */
	
	unsigned char *pinit = NULL;
	int i=0, k=0;
	pinit = user_data + DNS_FIX_HDR_SIZE;
	for(i=0;i<nbq;i++) {
		k=0;
		//On sauvegarde la position de chaque requete dans le paquet initial
		p->pos_query_in_frame[i] = pinit;
		
		while(*(pinit+k) != 0x00 && k < 253) {
			int nb_char = (int)*(pinit+k);
			for(int l=0;l<nb_char;l++){
				p->queries[i].qname[k] = (unsigned char) *(pinit + k + 1); 
				k++;
			}
			p->queries[i].qname[k] = '.';
			k+=1;
		}
		/*On termine  la chaine de caractère proprement*/
		p->queries[i].qname[k]	= '\0';
		
		/* On affecte es autres valeurs à la requête */
		p->queries[i].length	= k;
		p->queries[i].qtype	= *(pinit + k + 2);
		p->queries[i].qclass	= *(pinit + k + 4);
	
		//On rajoute un offset de manière à acceder à la requete suivante
		if(i==0) pinit = user_data+12+k+5;
		if(i!=0) pinit += k+5;
	}
	return 0;
}
void affiche_queries(dnspacket *p) {

	for(int i = 0;i<p->nb_queries;i++) {
		fprintf(stderr,"Query %d: %s\n",i,p->queries[i].qname);
	}

}

