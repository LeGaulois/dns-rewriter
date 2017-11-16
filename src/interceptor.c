#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <linux/ip.h>
/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <libnetfilter_queue/pktbuff.h>
#include "interceptor.h"
#include "logger.h"


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



static struct nlmsghdr *
nfq_hdr_put(char *buf, int type, uint32_t queue_num)
{
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type	= (NFNL_SUBSYS_QUEUE << 8) | type;
	nlh->nlmsg_flags = NLM_F_REQUEST;

	struct nfgenmsg *nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = AF_UNSPEC;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(queue_num);

	return nlh;
}


static void
nfq_send_verdict(interceptor *itcp, int queue_num, uint32_t id)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct nlattr *nest;

	nlh = nfq_hdr_put(buf, NFQNL_MSG_VERDICT, queue_num);
	nfq_nlmsg_verdict_put(nlh, id, NF_ACCEPT);

	/* example to set the connmark. First, start NFQA_CT section: */
	nest = mnl_attr_nest_start(nlh, NFQA_CT);

	/* then, add the connmark attribute: */
	mnl_attr_put_u32(nlh, CTA_MARK, htonl(42));
	/* more conntrack attributes, e.g. CTA_LABEL, could be set here */

	/* end conntrack section */
	mnl_attr_nest_end(nlh, nest);

	if (mnl_socket_sendto(itcp->nl, nlh, nlh->nlmsg_len) < 0) {
		perror("mnl_socket_send");
		exit(EXIT_FAILURE);
	}
}

static int queue_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nfqnl_msg_packet_hdr *ph = NULL;
	struct nlattr *attr[NFQA_MAX+1] = {};
	uint32_t id = 0, skbinfo;
	struct nfgenmsg *nfg;
	uint16_t plen;
	interceptor *itcp = NULL;
	
    itcp = (interceptor*)(data);

	if (nfq_nlmsg_parse(nlh, attr) < 0) {
		perror("problems parsing");
		return MNL_CB_ERROR;
	}

	nfg = mnl_nlmsg_get_payload(nlh);

	if (attr[NFQA_PACKET_HDR] == NULL) {
		fputs("metaheader not set\n", stderr);
		return MNL_CB_ERROR;
	}

	ph = mnl_attr_get_payload(attr[NFQA_PACKET_HDR]);

	plen = mnl_attr_get_payload_len(attr[NFQA_PAYLOAD]);
	void *payload = mnl_attr_get_payload(attr[NFQA_PAYLOAD]);

	skbinfo = attr[NFQA_SKB_INFO] ? ntohl(mnl_attr_get_u32(attr[NFQA_SKB_INFO])) : 0;

	if (attr[NFQA_CAP_LEN]) {
		uint32_t orig_len = ntohl(mnl_attr_get_u32(attr[NFQA_CAP_LEN]));
		if (orig_len != plen)
			printf("truncated ");
	}

	if (skbinfo & NFQA_SKB_GSO)
		printf("GSO ");

	id = ntohl(ph->packet_id);
	
	struct pkt_buff *pbuff = NULL;
	pbuff = pktb_alloc(AF_INET, payload, plen, 0);
	
	if (pbuff==NULL){
	    fprintf(stderr,"Erreur de recuperation du payload\n");
	}
	else {
	    struct iphdr *ip = NULL;
	    ip = nfq_ip_get_hdr(pbuff);
	    fprintf(stderr,"TTL:%d - protocol: %d - saddr: %08x\n", ip->ttl, ip->protocol, ip->saddr);
	    //free(ip);
	    pktb_free(pbuff);
	}
	
	printf("packet received (id=%u hw=0x%04x hook=%u, payload len %u",
		id, ntohs(ph->hw_protocol), ph->hook, plen);

	/*
	 * ip/tcp checksums are not yet valid, e.g. due to GRO/GSO.
	 * The application should behave as if the checksums are correct.
	 *
	 * If these packets are later forwarded/sent out, the checksums will
	 * be corrected by kernel/hardware.
	 */
	if (skbinfo & NFQA_SKB_CSUMNOTREADY)
		printf(", checksum not ready");
	puts(")");

	nfq_send_verdict(itcp,ntohs(nfg->res_id), id);

	return MNL_CB_OK;
}

int interceptor_worker(int queue_num)
{
    interceptor *itcp = NULL;
	struct nlmsghdr *nlh;

    itcp = interceptor_init();
    
    if (itcp==NULL) return -1;
    
    itcp->sizeof_buf = 0xffff + (MNL_SOCKET_BUFFER_SIZE/2);
    itcp->queue_cb = queue_cb;
    
    
	itcp->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (itcp->nl == NULL) {
		SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_open: %s", strerror(errno));
		return -1;
	}

	if (mnl_socket_bind(itcp->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_bind: %s", strerror(errno));
		return -1;
	}
	
	itcp->portid = mnl_socket_get_portid(itcp->nl);

	itcp->buf = malloc(itcp->sizeof_buf);
	if (!itcp->buf) {
		SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'allocation \
du buffer de réception: %s", strerror(errno));
		return -1;
	}

	/* PF_(UN)BIND is not needed with kernels 3.8 and later */
	nlh = nfq_hdr_put(itcp->buf, NFQNL_MSG_CONFIG, 0);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_UNBIND);

	if (mnl_socket_sendto(itcp->nl, nlh, nlh->nlmsg_len) < 0) {
		SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_send: %s", strerror(errno));
		return -1;
	}

	nlh = nfq_hdr_put(itcp->buf, NFQNL_MSG_CONFIG, 0);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_PF_BIND);

	if (mnl_socket_sendto(itcp->nl, nlh, nlh->nlmsg_len) < 0) {
		SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_send: %s", strerror(errno));
		return -1;
	}

	nlh = nfq_hdr_put(itcp->buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_cmd(nlh, AF_INET, NFQNL_CFG_CMD_BIND);

	if (mnl_socket_sendto(itcp->nl, nlh, nlh->nlmsg_len) < 0) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_send: %s", strerror(errno));
		return -1;
	}

    
	nlh = nfq_hdr_put(itcp->buf, NFQNL_MSG_CONFIG, queue_num);
	nfq_nlmsg_cfg_put_params(nlh, NFQNL_COPY_PACKET, 0xffff);

    
	mnl_attr_put_u32(nlh, NFQA_CFG_FLAGS, htonl(NFQA_CFG_F_GSO));
	mnl_attr_put_u32(nlh, NFQA_CFG_MASK, htonl(NFQA_CFG_F_GSO));

	if (mnl_socket_sendto(itcp->nl, nlh, nlh->nlmsg_len) < 0) {
        SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_sendto: %s", strerror(errno));
		return -1;
	}

	/* ENOBUFS is signalled to userspace when packets were lost
	 * on kernel side.  In most cases, userspace isn't interested
	 * in this information, so turn it off.
	 */
	 
	
	itcp->ret = 1;
	mnl_socket_setsockopt(itcp->nl, NETLINK_NO_ENOBUFS, &(itcp->ret), sizeof(int));

    INTERCEPTOR = itcp;
	for (;;) {
		itcp->ret = mnl_socket_recvfrom(itcp->nl, itcp->buf, 
		        itcp->sizeof_buf);
		        
		if (itcp->ret == -1) {
			SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_socket_recvfrom: %s", strerror(errno));
		return -1;
		}

		itcp->ret = mnl_cb_run(itcp->buf, itcp->ret, 0, 
		    itcp->portid, itcp->queue_cb, itcp);
		    
		if (itcp->ret < 0){
			SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'appel \
à mnl_cb_run: %s", strerror(errno));
		return -1;
		}
	}

	mnl_socket_close(itcp->nl);
	

	return 0;
}
