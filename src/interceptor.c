#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <libmnl/libmnl.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_queue/pktbuff.h>

#include "parser_tools.h"
#include "interceptor.h"
#include "logger.h"
#include "dnsparser.h"
#include "dnsrewriter.h"
#include "hash.h"
#include "workers.h"
#include "logger.h"



extern ntree_root *ROOT;
extern hashtable *HASHTABLE_Q;
extern hashtable *HASHTABLE_R;
interceptor *INTERCEPTOR;
extern worker *ME;


/**
 * INTERCEPTOR_INIT
 * Initialise la structure interceptor.
 *
 * Valeurs de retour
 * @PTR_INTERCEPTOR: pointeur sur la structure interceptor
 * @NULL -> Erreur
 */
interceptor* interceptor_init(){
    interceptor *itcp = NULL;
    
    itcp = calloc(1, sizeof(interceptor));
    
    if(itcp==NULL){
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] Erreur d'allocation \
de la structure interceptor.", ME->number);
        return NULL;
    }
    memset(itcp,0,sizeof(interceptor));
    return itcp;
}


/**
 * INTERCEPTOR_FREE
 * Libére la structure interceptor.
 */
void interceptor_free(interceptor *itcp){
    mnl_socket_close(itcp->nl);
    free(itcp->buf);
    free(itcp);
}

/*
static int handle_query(struct pkt_buff *pbuff, dnspacket* p, uint32_t payload_len, unsigned char* payload_data) {

   int i=0; 
   int result_rewrite=0;
   do {
     result_rewrite = rewrite_dns(pbuff,p->queries[i].qname,HASHTABLE_Q,p,REWRITE_Q);
     fprintf(stderr,"QUERY REWRITING STATUS %d !\n\n",result_rewrite);
     i++;
   } while(i<p->nb_queries && result_rewrite == 1);
    	
   if(result_rewrite == 1) {	 	
      set_checksum_to_zero(pbuff);   
      memcpy(payload_data,pbuff->data,pbuff->len);
      return result_rewrite;
   }
   else return 0;

}
*/


static int handle_dns(dnspacket* p, uint32_t payload_len, unsigned char* payload_data, uint8_t type) 
{ 
   int result_rewrite=0;
   
    if(type == REWRITE_R){
        result_rewrite = rewrite_dns(p,
            p->query.qname,HASHTABLE_R,REWRITE_R);
    }
    else if(type == REWRITE_Q){
        result_rewrite = rewrite_dns(p,
            p->query.qname,HASHTABLE_Q,REWRITE_Q);
    }
     else return -1;
     
     fprintf(stderr,"REPLY REWRITING STATUS %d !\n\n",result_rewrite);
     
     if(result_rewrite == 1) { 	
        set_checksum_to_zero(p->skb);
        memcpy(payload_data,p->skb->data,p->skb->len);
        return result_rewrite;
     }
     else return 0;
} 



int handle_getdata(struct nfq_data *nfad, dnspacket **p,
        unsigned char **payload_data)
{
	struct pkt_buff *pbuff = NULL;
	uint32_t payload_len = 0;

    if((!nfad)||(!p)) return -1;
		
	payload_len = nfq_get_payload(nfad, payload_data);
	
	if (payload_len==0){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Pas de payload reçu.",ME->number);
        return -1;
	}
	
	/**
	 * On doit ajouter de la mémoire supplémentaire à l'allocation
	 * car le mangle dynamique n'est pas faisable
	 */
	pbuff = pktb_alloc(AF_INET, payload_data, payload_len, 10); 
	
	if (!pbuff){
	    SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Erreur de création du pkt_buff: %s.",ME->number, strerror(errno));
        return -1;
	}
	
	*p = init_struct_dnspacket();
	    
	if(!*p){
	    SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur de creation de la structure dnspacket.",ME->number);
        return -1;
	}
	
	(*p)->skb = pbuff;
	return payload_len;
}


/**
 * QUEUE_CB
 * Traitement des paquets recus dans la file netfilter.
 */
static int handle_packet(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) 
{
	if(!nfad) return 0;
	
	dnspacket *p = NULL;
	struct pkt_buff *pbuff = NULL;
	unsigned char* payload_data = NULL;
	int id = 0;
	uint32_t payload_len = 0;
	int result = 0, result_parsing =0;
	
	
    payload_len = handle_getdata(nfad, &p,&payload_data);
	
	if(payload_len <= 0){
	    nfq_set_verdict(qh,id, NF_ACCEPT,0,0);
	    return MNL_CB_OK;
	}
	
	result_parsing = dnspacket_parse(p);
	    
	if(result_parsing != 0){
	    SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
La trame reçu ne sera pas traitée.",ME->number);
        nfq_set_verdict(qh,id, NF_ACCEPT,0,0);
	    return MNL_CB_OK;
	}
	    
	if(p->nb_queries != 0 && p->nb_replies == 0)  {
	    result = handle_dns(p,payload_len,payload_data,
	            REWRITE_Q);
	            
        if(result == 0){
	        nfq_set_verdict(qh,id, NF_ACCEPT,0,0);
        }
	    else{
	        nfq_set_verdict(qh,id,NF_ACCEPT,
	            payload_len,payload_data);
	   }
	}
	else if(p->nb_queries != 0 && p->nb_replies != 0) {
        result = handle_dns(p,payload_len,
            payload_data, REWRITE_R);
            
	    if(result == 0) nfq_set_verdict(qh,id, NF_ACCEPT,0,0);
	    else{
	        nfq_set_verdict(qh,id,NF_ACCEPT,payload_len,payload_data);
     	}
    }
	else {
	    return -1;
	}
	free(p);
	pktb_free(pbuff);
	
	return result;
}


/**
 * INTERCEPTOR_WORKER
 * Lance l'écoute sur la file nf_queue.
 *
 * Parametres
 *  @queue_num: numéro de la queue netfilter
 *
 * Valeurs de retour
 * @0  -> SUCCESS
 * @-1 -> ERREUR
 */
int interceptor_worker(int queue_num)
{
    interceptor *itcp       = NULL;
    struct nfq_handle *h    = NULL;
	struct nfq_q_handle *qh = NULL;

	char buf[4096] __attribute__ ((aligned));
	int fd, rv;
	
    itcp = interceptor_init();
    
    if(!itcp){
        ME->status = CRITICAL_ERROR;
        return -1;
    }
    
	h = nfq_open();
	
	if (!h) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur de création de la file netfilter.",ME->number);
        return -1;
	}

	if (nfq_unbind_pf(h, AF_INET) < 0) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur lors de l'appel de la fonction nfq_unbind().",ME->number);
        return -1;
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur lors de l'appel de la fonction nfq_bind_pf().",ME->number);
		return -1;
	}
	
	qh = nfq_create_queue(h, queue_num, &handle_packet, NULL);
	if (!qh) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur lors de l'appel de la fonction nfq_create_queue().",ME->number);
		return -1;
	}

	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur lors du poistionnement du mode COPY_PACKET.",ME->number);
		return -1;
	}
	
	itcp->queue_cb = handle_packet;
	fd = nfq_fd(h);
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		nfq_handle_packet(h, buf, rv);
	}

    
    return 0;
}
