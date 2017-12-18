#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <string.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>


int
on_packet(struct nfq_q_handle *qh,
		struct nfgenmsg *nfmsg,
		struct nfq_data *nfad, void *data)
{
	int plen;
	int id;
	unsigned char *p;
	uint32_t mark;
	size_t i, packet_size;
	int wchartstat;
    struct pkt_buff *pktbuff; 
    struct nfqnl_msg_packet_hw *hw = NULL;
    
    /*
     * Renvoie les metaheader
     */
	struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
	
	if (ph) {
		id = ntohl(ph->packet_id);
	} else {
		return -1;
	}

    /*
     * Récupére le payload de nfq_data
     * C'est à dire ce qui n'est pas metadata
     */
	if ((plen = nfq_get_payload(nfad, &p)) < 0) {
	    return -1;
	}

    /*
     * On récupere l'adresse MAC source
     */
    hw = nfq_get_packet_hw(nfad); 	
    //uint16_t sizehw = nflog_get_msg_packet_hwhdrlen(nfad);
    fprintf(stderr,"ID: %d -Len: %04x -Padding: %04x - protocol: %04x\n- MAC:%02x:%02x:%02x:%02x:%02x:%02x\n DATA: %s\n",id,hw->hw_addrlen, hw->_pad,ph->hw_protocol, hw->hw_addr[0],hw->hw_addr[1],hw->hw_addr[2],hw->hw_addr[3],hw->hw_addr[4],hw->hw_addr[5], p );
     
    //packet_size = mnl_nlmsg_get_payload_len(qh->h->nfnlh->);
    
    
    //pktbuff = pktb_alloc(AF_INET, (void*)(p),  ,0);
	//nfq_set_verdict(u->qh, id, NF_DROP, 0, NULL);
	//nfq_set_verdict(u->qh, id, NF_ACCEPT, plen, (unsigned char *)p);

	//mark = nfq_get_nfmark(nfad);
	//nfq_set_verdict(u->qh, id, NF_DROP, 0, NULL);
	//add_to_queue(u, p, id, plen, weight);


	return 1;
}


int
main(int argc, char *argv[])
{
	struct nfq_handle *h;
	struct nfq_q_handle *nfqh;
	int fd;
	char buf[1600];
	int r = EXIT_FAILURE;
	struct sigaction action;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s config.cfg\n", argv[0]);
		return EXIT_FAILURE;
	}


	h = nfq_open();
	if (!h) {
		fprintf(stderr, "nfq_open() failed\n");
		return EXIT_FAILURE;
	}

    /*
     * Pour les vieilles versions de linux (<3.8)
     */
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nfq_unbind_pf() failed\n");
		goto fail_unbind;
	}

	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "nfq_bind_pf() failed\n");
		goto fail_bind;
	}

    
	nfqh = nfq_create_queue(h, atoi(argv[1]), &on_packet, NULL);
	if (!nfqh) {
		fprintf(stderr, "nfq_create_queue() with queue failed\n");
		goto fail_queue;
	}

	if (nfq_set_mode(nfqh, NFQNL_COPY_PACKET, 1600) < 0) {
		fprintf(stderr, "nfq_set_mode() failed\n");
		goto fail_mode;
	}

	if (nfq_set_queue_maxlen(nfqh, 100) < 0) {
		fprintf(stderr, "nfq_set_queue_maxlen() failed with qlen\n");
		goto fail_mode;
	}


	fd = nfq_fd(h);
	for (;;) {
		int rv;

		rv = recv(fd, buf, sizeof(buf), 0);
		if ((rv < 0) && (errno != EINTR)) {
			fprintf(stderr, "recv() on queue returned %d (%s)\n", rv, strerror(errno));
			fprintf(stderr, "Queue full? Current queue size, you can increase 'nfqlen' parameter in damper.conf\n");
			continue; /* don't stop after error */
		}

		nfq_handle_packet(h, buf, rv);
		fprintf(stderr,"RAW BUFFER (%d):%s\n\n", rv,buf);
	}


	r = EXIT_SUCCESS;

fail_mode:
	nfq_destroy_queue(nfqh);

fail_queue:
fail_bind:
fail_unbind:
	nfq_close(h);


	return r;
}
