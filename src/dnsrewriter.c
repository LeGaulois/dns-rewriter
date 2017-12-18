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
#include "workers.h"
#include "logger.h"
#include "tools.h"


/*
 * Variables externes globales
 */
extern ntree_root *ROOT;
extern hashtable *HASHTABLE_Q;
extern hashtable *HASHTABLE_R;
extern worker *ME;


/**
 * MOVE_RAPPEL_BYTES
 * Ajuste l'ensemble des pointeurs de compression
 * en fonction de la différence de longueur du champ
 * query réécris
 */
void move_rappel_bytes(dnspacket* p, char* new_str)
{
	struct iphdr *iph = NULL;
	struct udphdr *udph = NULL;
	uint8_t *dnspayload_data	= NULL;
	uint8_t dnspayload_length	= 0;
	int i,k=0;
	
	iph = (struct iphdr *)nfq_ip_get_hdr(p->skb);
	nfq_ip_set_transport_header(p->skb, iph);
	
	udph = (struct udphdr *)nfq_udp_get_hdr(p->skb);
	dnspayload_data = pktb_transport_header(p->skb) + UDP_HDR_SIZE + DNS_FIX_HDR_SIZE;
	dnspayload_length = udph->len - UDP_HDR_SIZE - DNS_FIX_HDR_SIZE;
	

	for(i=0;i<dnspayload_length-1;i++) {
	  if(dnspayload_data[i] == 0xc0) {
	    k++;
	    
	    /** 
	     * En théorie, pas besoin de décaler le 1èer rappel
	     *  (entête UDP et DNS fixes)
	     * On ajuste la reference du pointeur de compression
	     * en fonction de la différence de longueur du champ
	     * query réécris 
	     */
	    if(k>1) {
	      int diff = p->query.length - get_len_qfmt(new_str);
	      dnspayload_data[i+1] -= diff;
	    }
	  }
	}
}


/**
 * SET_CHECKSUM_TO_ZERO
 * Fixe le checksum UDP à zéro.
 *
 * Valeurs de retour
 * 0  -> SUCCESS
 * -1 -> ERROR
 */
int set_checksum_to_zero(struct pkt_buff *pkb) 
{
    struct iphdr *iph = NULL;
    uint8_t *udphdr_checksum = NULL;
    

	if(!pkb) return -1;
	
	iph = (struct iphdr *) nfq_ip_get_hdr(pkb);
	if(!iph) return -1;
	
	
	nfq_ip_set_transport_header(pkb,iph);
	udphdr_checksum = pktb_transport_header(pkb);

	if(!udphdr_checksum) return -1;
	
	udphdr_checksum[6] = 0x00;
	udphdr_checksum[7] = 0x00;
	
	return 0;	
}


/**
 * REPLACE_QUERY
 * Calcul le nouveau checksum IP et effectue une modification
 * de la valeur de l'octet de compression DNS
 */
int replace_query(dnspacket *p, char* to_insert, uint8_t type) 
{
	int result;
	struct iphdr *iph = NULL;
	
	iph = (struct iphdr *)nfq_ip_get_hdr(p->skb);
	nfq_ip_set_transport_header(p->skb, iph);
	
	/**
	 * loffset demandé par mangle correspond à la distance
	 * entre les data du paquet UDP  (et non le header udp)
	 * et notre match
	 * 12 -> taille entête DNS
	 */
	result = nfq_udp_mangle_ipv4(p->skb,12,p->query.length, 
	    to_insert, get_len_qfmt(to_insert) );
	
	if( (result == 1)&&(type == REWRITE_R)){
	  /*On décale les octets de RAPPEL si c'est une réponse*/
        move_rappel_bytes(p,to_insert);
        return 0;
	}
	return result;
}


/**
 * REWRITE_DNS
 * Réécris la requête DNS en fonction de l'adresse IP du client
 * et du FQDN à résoudre ou bien la réponse renvoyé par 
 * le resolveur.
 *
 * hashtable représente ici soit la hashtable_q (qr -> q_rewrited)
 * soit la hashtable_r (transaction_id -> qr)
 *
 * Valeurs de retour
 * 0 ou 1 -> réécriture effectuée
 *  -1    -> pas de réécriture
 */
int rewrite_dns (dnspacket* packet, unsigned char* query, 
        hashtable* hashtable, uint8_t type)
{
    int ret = -1;
    
    if(type == REWRITE_Q) {
        ret = rewrite_dns_query(packet,query,hashtable);
    }
   
    else {
        ret = rewrite_dns_response(packet,query,hashtable);
    }
    return ret;
}


/**
 * REWRITE_DNS_RESPONSE
 * Réécris la réponse DNS renvoyé par le resolveur
 * en fonction de la réécriture effectuée lors de la query.
 *
 * 
 * Valeurs de retour
 * 0 ou 1 -> réécriture effectuée
 *  -1    -> pas de réécriture
 */
int rewrite_dns_response(dnspacket* packet, unsigned char* query,
            hashtable* hashtable)
{
    char *to_insert		    = NULL;
	dns_t *data		        = NULL;
	char *finalrewrite	    = NULL;
	struct iphdr *iph	    = NULL;
	void *ntree_finalnode	= NULL;
	
	finalrewrite    = calloc(253,sizeof(char));
	to_insert		= calloc(253,sizeof(char));
	
	
	/**
	 * Récupération du label
	 */
	iph = (struct iphdr *)nfq_ip_get_hdr(packet->skb);
	ntree_finalnode = (char *)(ntree_root_lookup(ROOT,iph->daddr));
	
	if(!ntree_finalnode){
	     SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID %s] Aucun pop trouvé pour l'adresse IP %s",
         ME->number, packet->transaction_id, uint32_t_to_char(iph->daddr));
         return -1;
	}
	
	SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID %s] l'adresse IP %s appartient au pop %s.",
         ME->number, packet->transaction_id,
         uint32_t_to_char(iph->daddr), ntree_finalnode);
         
	
	strtostr_replace(ntree_finalnode,"$pop",
	        (char *)(packet->query.qname),finalrewrite);
	data = (dns_t*) hashtable_get_element(HASHTABLE_R, finalrewrite, NULL);
	   
	if(data) {
	     strtodns_qfmt(data->rewrited,to_insert);
	     packet->nb_q_rewrited += 1;
	     return replace_query(packet,to_insert,REWRITE_R);
	}
	else {
	    SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID %s] Impossible de trouver la query d'origine.",
         ME->number, packet->transaction_id);
	}

    return -1;
}


/**
 * REWRITE_DNS_QUERY
 * Réécris la requête DNS envoyé par le client
 * 
 * Valeurs de retour
 * 0 ou 1 -> réécriture effectuée
 *  -1    -> pas de réécriture
 */
int rewrite_dns_query (dnspacket* packet, unsigned char* query,
            hashtable* hashtable)
{
    struct iphdr *iph	    = NULL;
	void *ntree_finalnode	= NULL;
	dns_t *dns_final_elem 	= NULL;
	char *finalrewrite	    = NULL;
	char *to_insert		    = NULL;
	char *ipaddress         = NULL;
	int ret                 = -1;
	
	finalrewrite    = calloc(253,sizeof(char));
	to_insert	    = calloc(253,sizeof(char));
		
	iph = (struct iphdr *)nfq_ip_get_hdr(packet->skb);
	ntree_finalnode = (char *)(ntree_root_lookup(ROOT,iph->daddr));
	
	
	if(!ntree_finalnode){
	     SLOGL_vprint(SLOGL_LVL_INFO,
           "[worker %d, ID %s] Aucun pop trouvé pour l'adresse IP %s",
            ME->number, packet->transaction_id, uint32_t_to_char(iph->daddr));
         return -1;
	}
	
	ipaddress = convert_u32_ipaddress_tostr(iph->daddr);
	SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID %s] l'adresse IP %s appartient au pop %s.",
         ME->number, packet->transaction_id, ipaddress, ntree_finalnode);
         
    free(ipaddress);
	dns_final_elem = (dns_t*) hashtable_get_element(HASHTABLE_Q, 
	        (char *)(packet->query.qname),NULL);
	        
	
	if(dns_final_elem) {
	    SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID:%s] la query %s sera reecrite en  %s",
         ME->number, packet->transaction_id,
         packet->query.qname, dns_final_elem->rewrited);
         
	    strtostr_replace("$pop",ntree_finalnode,
	            dns_final_elem->rewrited,finalrewrite);
		strtodns_qfmt(finalrewrite,to_insert);
		
		SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID %s] Query réécrite en %s",
         ME->number, packet->transaction_id, finalrewrite);
         
		ret = replace_query(packet,to_insert,REWRITE_Q);
	}
	
	else{
	    SLOGL_vprint(SLOGL_LVL_INFO,
        "[worker %d, ID %s] Pas de correspondance trouvée pour la query %s",
         ME->number, packet->transaction_id, packet->query.qname);
         ret = -1;
	}
	free(finalrewrite);
	free(to_insert);
	return ret;
}
