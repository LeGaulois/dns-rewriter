#ifndef INTERCEPTOR_H
#define INTERCEPTOR_H

typedef struct interceptor interceptor;


struct interceptor {
    struct mnl_socket   *nl;
    char                *buf;    
    size_t              sizeof_buf;
    int                 ret;
    unsigned int        portid; 
    int                 (*queue_cb)(const struct nlmsghdr*, void *);       
};

interceptor* interceptor_init();

#endif

