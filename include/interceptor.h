#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H
#include "dnsparser.h"
typedef struct interceptor interceptor;


struct interceptor {
    struct mnl_socket   *nl;
    char                *buf;    
    size_t              sizeof_buf;
    int                 ret;
    unsigned int        portid; 
    int                 (*queue_cb)(struct nfq_q_handle *qh,struct nfgenmsg *nfmsg,struct nfq_data *nfad, void *data);   
};

interceptor* interceptor_init();
int interceptor_worker(int queue_num);
void interceptor_free(interceptor *itcp);
//static int handle_query(struct pkt_buff *pbuff, dnspacket* p, uint32_t payload_len, unsigned char* payload_data);
static int handle_dns(struct pkt_buff *pbuff, dnspacket* p, uint32_t payload_len, unsigned char* payload_data, uint8_t type);
#endif

