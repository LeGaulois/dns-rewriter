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

#include "parser_tools.h"
#include "dnsparser.h"
#include "ntree_binary.h"
#include "iptools.h"
#include "hash.h"
#include "dns_translation.h"
#include "tools.h"
#include "interceptor.h"
#include "dnsrewriter.h"



/*
 * Variables externes globales
 */
extern ntree_root *ROOT;
extern hashtable *HASHTABLE_Q;
extern hashtable *HASHTABLE_R;


int move_rappel_bytes(struct pkt_buff *pbuff, dnspacket* p, char* new_str){
	
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	uint8_t *dnspayload_data	= NULL;
	uint8_t dnspayload_length	= 0;
	int i,k=0;
	
	iph = (struct iphdr *)nfq_ip_get_hdr(pbuff);
	nfq_ip_set_transport_header(pbuff, iph);
	
	udph = (struct udphdr *)nfq_udp_get_hdr(pbuff);
	dnspayload_data = pktb_transport_header(pbuff) + UDP_HDR_SIZE + DNS_FIX_HDR_SIZE;
	dnspayload_length   = udph->len - UDP_HDR_SIZE - DNS_FIX_HDR_SIZE;
	

	for(i=0;i<dnspayload_length-1;i++) {
	  if(dnspayload_data[i] == 0xc0) {
	    k++;
	    /* En théorie, pas besoin de décaler le 1èer rappel (HDR DNS & UDP fixes) */
	    
	    if(k>1) {
	      int diff = p->queries[0].length - get_len_qfmt(new_str);
	      dnspayload_data[i+1] -= diff;
	    }
	    else continue;
	  
	  }
	  else continue;
	
	
	}
	return 1;
	

}
int set_checksum_to_zero(struct pkt_buff *pkb) {

	/* on vérifie que le *pkt_buff existe */
	if(!pkb) return -1;
	
	struct iphdr *iph = NULL;
	iph = (struct iphdr *) nfq_ip_get_hdr(pkb);
	
	/* On vérifie que le *IPH existe */
	if(!iph) return -2;
	
	
	nfq_ip_set_transport_header(pkb,iph);
	uint8_t *udphdr_checksum = NULL;
	udphdr_checksum = pktb_transport_header(pkb);
	
	/* On vérifie que le *udphdr_checksum existe */
	if(!udphdr_checksum) return -3;
	
	udphdr_checksum[6] = 0x00;
	udphdr_checksum[7] = 0x00;
	
	return 0;	
}

int replace_q(struct pkt_buff *pkb, dnspacket *packet, int nq, char* to_insert, uint8_t type) {

	uint8_t offset = 0;
	int result;
	struct iphdr *iph = NULL;
	iph = (struct iphdr *)nfq_ip_get_hdr(pkb);
	nfq_ip_set_transport_header(pkb, iph);
	uint8_t *udphdr_pos = NULL;
	udphdr_pos = pktb_transport_header(pkb);
	offset = packet->pos_query_in_frame[nq] - (udphdr_pos + UDP_HDR_SIZE); 
	//loffset demandé par mangle correspond à la distance entre les data du paquet UDP  (et non le header udp) et notre match
	result = nfq_udp_mangle_ipv4(pkb,offset,packet->queries[nq].length, to_insert,get_len_qfmt(to_insert));
	if(result == 1) {
	  //On décale les octets de RAPPEL si c'est une réponse
	  if (type == REWRITE_R) result = move_rappel_bytes(pkb,packet,to_insert);
	}
	return result;
}


/* FONCTION DE REECRITURE DNS

Elle est destinée à etre utilisée par le coeur du programme (main).

 * hashtable représente ici soit la hashtable_q (qr -> q_rewrited)
 * soit la hashtable_r (transaction_id -> qr)
*/

int rewrite_dns (struct pkt_buff *sock_buff, unsigned char* query, hashtable* hashtable, dnspacket* packet, uint8_t type) {
	
   if(type == REWRITE_Q) {
   
	struct iphdr *iph	= NULL;
	void *ntree_finalnode	= NULL;
	dns_t *dns_final_elem 	= NULL;
	char *finalrewrite	= NULL;
	char *to_insert		= NULL;
	
	finalrewrite 		= calloc(253,sizeof(char));
	to_insert		= calloc(253,sizeof(char));
		
	//RECUPERATION DU LABEL
	
	iph = (struct iphdr *)nfq_ip_get_hdr(sock_buff);
	uint32_t ipadd;

	ipadd = uint32_t_invert(ip_addr_invert(iph->saddr));
	ntree_finalnode = (char *)(ntree_root_lookup(ROOT,ipadd));
	
	//RECUPERATION DE L'URL DE FIN
	fprintf(stderr,"Q-FinalNodeChar : %s\n",ntree_finalnode);
	
	if(ntree_finalnode) {
	  if(packet->nb_queries ==1 ) {
	 	dns_final_elem = (dns_t*) hashtable_get_element(HASHTABLE_Q, packet->queries[0].qname,NULL);
		if(dns_final_elem) {
	  	   strtostr_replace("$pop",ntree_finalnode,dns_final_elem->rewrited,finalrewrite);
		   strtodns_qfmt(finalrewrite,to_insert);
		   fprintf(stderr,"HT_R->nb_entries : %d\nfinalre = %s\n",HASHTABLE_R->nbentries, finalrewrite);
		   int replace = replace_q(sock_buff,packet,i,to_insert,REWRITE_Q);
		   
		   return replace;
	  	}
	  	else return -1;
	  } else return -2
	} else return -3;
	return 0;
   }
   
   if(type == REWRITE_R) {

	char *to_insert		= NULL;
	dns_t *data		= NULL;
	char *finalrewrite	= NULL;
	struct iphdr *iph	= NULL;
	void *ntree_finalnode	= NULL;
	
	finalrewrite 		= calloc(253,sizeof(char));
	to_insert		= calloc(253,sizeof(char));
	
	//RECUPERATION DU LABEL
	
	iph = (struct iphdr *)nfq_ip_get_hdr(sock_buff);
	uint32_t ipadd;

	ipadd = uint32_t_invert(ip_addr_invert(iph->daddr));
	ntree_finalnode = (char *)(ntree_root_lookup(ROOT,ipadd));
	
	fprintf(stderr,"R- FinalNodeChar : %s\n",ntree_finalnode);
	
	if(ntree_finalnode) {
	if(packet->nb_queries ==1 ) {
	
	   strtostr_replace(ntree_finalnode,"$pop",packet->queries[0].qname,finalrewrite);
	   fprintf(stderr,"test : finalrewrite = %s\n", finalrewrite);
	   data = (dns_t*) hashtable_get_element(HASHTABLE_R, finalrewrite, NULL);
	   if(data != NULL) {
	     strtodns_qfmt(data->rewrited,to_insert);
	     packet->nb_q_rewrited += 1;
	     int replace = replace_q(sock_buff,packet,i,to_insert,REWRITE_R);
	     return replace;
	   }
	   else return -1;
	} else return -2;   
   } else return -3;
   return 0;
}
