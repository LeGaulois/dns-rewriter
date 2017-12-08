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
/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_queue/pktbuff.h>

#include "parser_tools.h"
#include "interceptor.h"
#include "logger.h"
#include "dnsparser.h"
#include "dnsrewriter.h"
#include "hash.h"


extern ntree_root *ROOT;
extern hashtable *HASHTABLE_Q;
extern hashtable *HASHTABLE_R;
//extern interceptor *INTERCEPTOR;
interceptor *INTERCEPTOR;


interceptor* interceptor_init(){
    interceptor *itcp = NULL;
    
    itcp = calloc(1, sizeof(interceptor));
    
    if(itcp==NULL){
        SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur d'allocation \
de la structure interceptor");
        return NULL;
    }
    memset(itcp,0,sizeof(interceptor));
    return itcp;
}

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
static int handle_dns(struct pkt_buff *pbuff, dnspacket* p, uint32_t payload_len, unsigned char* payload_data, uint8_t type) {
 
   int i=0;
   int result_rewrite=0;
   do {
     if(type == REWRITE_R) result_rewrite = rewrite_dns(pbuff,p->queries[i].qname,HASHTABLE_R,p,REWRITE_R);
     else if(type == REWRITE_Q) result_rewrite = rewrite_dns(pbuff,p->queries[i].qname,HASHTABLE_Q,p,REWRITE_Q);
     else return -1;
     
     fprintf(stderr,"REPLY REWRITING STATUS %d !\n\n",result_rewrite);
     i++;
     
   } while(i<p->nb_queries && result_rewrite == 1);
     if(result_rewrite == 1) { 	
        set_checksum_to_zero(pbuff);
        memcpy(payload_data,pbuff->data,pbuff->len);
        return result_rewrite;
     }
     else return 0;
} 
static int queue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {


	if(!nfad) return NULL;
	
	struct nfqnl_msg_packet_hdr *ph;
	struct pkt_buff *pbuff = NULL;
	unsigned char* payload_data = NULL;
	int id = 0;
	uint32_t payload_len;
	int result = 0;
	
	printf("entering callback\n");
 
	ph = nfq_get_msg_packet_hdr(nfad);
	if (ph) {
		id = ntohl(ph->packet_id);
		fprintf(stderr,"\n-----------------NOUVEAU PAQUET RECU ! --------------\n hw_protocol=0x%04x hook=%u id=%u \n",
			ntohs(ph->hw_protocol), ph->hook, id);
	}
	
	payload_len = nfq_get_payload(nfad, &payload_data);
	//On doit ajouter de la mémoire supplémentaire à l'allocation car le mangle dynamique n'est pas faisable
	pbuff = pktb_alloc(AF_INET, payload_data, payload_len, 10); 
	
	if (pbuff==NULL){
	    fprintf(stderr,"Erreur de recuperation du payload\n");
	}
	else {
	    struct iphdr *ip = NULL;
	    ip = nfq_ip_get_hdr(pbuff);
	    if(ip == NULL) return NULL;
	    
	    
	    int nbq = get_nb_dnsquery(pbuff);
	    dnspacket *p = NULL;
	    p = init_struct_dnspacket(nbq);
	    int result_parsing = dns_req_parsing(pbuff,p,nbq);
	    
	    if(result_parsing == 0) {
	    	fprintf(stderr,"TransactionID : %s - Flags : %x - NbQ : %d - NbR : %d\n",p->transaction_id, p->flags,p->nb_queries,p->nb_replies);
	    	affiche_queries(p);
	    }
	    
	    if(p->nb_queries != 0 && p->nb_replies == 0)  {
	    	//int result = handle_query(pbuff,p,payload_len,payload_data);
	    	int result = handle_dns(pbuff,p,payload_len,payload_data, REWRITE_Q);
	    	if(result == 0) nfq_set_verdict(qh,id, NF_ACCEPT,0,0);
	    	else nfq_set_verdict(qh,id,NF_ACCEPT,payload_len,payload_data);
     		fprintf(stderr,"PBUFF->LEN : %d \t RESULT VERDICT : %d\n",pbuff->data_len,result);
	    }
	    else if(p->nb_queries != 0 && p->nb_replies != 0) {
	    	//int result = handle_reply(pbuff,p,payload_len,payload_data);
	    	int result = handle_dns(pbuff,p,payload_len,payload_data, REWRITE_R);
	    	if(result == 0) nfq_set_verdict(qh,id, NF_ACCEPT,0,0);
	    	else nfq_set_verdict(qh,id,NF_ACCEPT,payload_len,payload_data);
     	    }
	    else {
	    	//si une réponse sans question..huhul
	    	//penser aux sloglevel
	    	return NULL;
	    }
	    free(p);
	    pktb_free(pbuff);
	}
	return result;
	
}

int interceptor_worker(int queue_num)
{
    interceptor *itcp = NULL;
	//struct nlmsghdr *nlh;

    itcp = interceptor_init();
    
    	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	char buf[4096] __attribute__ ((aligned));
	int fd;
	int rv;
    
    if (itcp==NULL) return -1;
    
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}
	
	qh = nfq_create_queue(h, queue_num, &queue_cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}
	
	fd = nfq_fd(h);
	
	while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
		printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

    itcp->queue_cb = queue_cb;
    return 0;
}
