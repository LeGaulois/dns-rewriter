#ifndef GENERAL_H
#define GENERAL_H


#include <signal.h>

#define MAX_WORKERS 20

typedef struct dispatcher dispatcher;

struct dispatcher {
    /*GENERAL*/
    char            *parameters_file;
    char            *range_file;
    char            *dnsentry_file;
    
    /*LOGS*/
    char            *logs_dir;
    char            *log_general_prefix;
    unsigned int    debug_level:3;
    char            *log_rewrite_prefix; 
       
    /*WORKER*/ 
    int             nb_workers;
    int             first_query_queue;
    int             first_response_queue;
    int             running_worker;
    
    /*SHARED*/
    worker          **workerstab;
    int             *fd_shared;
};



int dispatcher_complete_from_file(dispatcher *dis);
struct dispatcher* dispatcher_init();
void dispatcher_free(dispatcher **dp,int close_shm_link);
void dispatcher_free_all_worker_except(dispatcher *dp, worker *c);

int dispatcher_init_tab_workers(struct dispatcher *dp);

    
void dispatcher_configure_signaux(void);
void dispatcher_gestionnaire_signal(int numero, 
            siginfo_t *info, void*data);
void dispatcher_kill_worker(dispatcher *dp);
    
    
/* FONCTIONS STATIQUES (POUR INFO)
statis int dispatcher_init_worker(dispatcher *dp, int queue_id,
    int position);
static int dispatcher_get_loglevel(dispatcher *dp, config_t *cfg)
static int dispatcher_get_logs_dir(dispatcher *dp, config_t *cfg)
static int dispatcher_get_log_general_prefix(
        dispatcher *dp, config_t *cfg)
static int dispatcher_get_log_write_prefix(
    dispatcher *dp, config_t *cfg)
static int dispatcher_get_rangefile(dispatcher *dp, config_t *cfg);
static int dispatcher_get_dnsentryfile(dispatcher *dp, config_t *cfg);
static void dispatcher_get_nbworkers(dispatcher *dp, config_t *cfg);
static int dispatcher_get_queue_id(dispatcher *dp, config_t *cfg);
*/

#endif
