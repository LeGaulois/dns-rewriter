#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

#include "dnsparser.h"
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct interceptor interceptor;


struct interceptor {
    struct nfq_handle   *h;
	struct nfq_q_handle *qh;  
};

interceptor* interceptor_init();
int interceptor_worker(int queue_num);
void interceptor_free(interceptor *itcp);
int nfq_send_verdict(struct nfq_q_handle *qh, uint32_t id,
    uint32_t verdict, uint32_t datalen,
    const unsigned char *buf, dnspacket *p);

#endif

