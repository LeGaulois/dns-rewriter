#ifndef GENERAL_H
#define GENERAL_H


#include <signal.h>

#define MAX_WORKERS 20

typedef struct controller controller;

struct controller {
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
    unsigned int    stopapp;
    
    /*SHARED*/
    worker          **workerstab;
};



int controller_complete_from_file(controller *dis);
struct controller* controller_init();
void controller_free(controller **dp,int close_shm_link);
void controller_free_all_worker_except(controller *dp, worker *c);

int controller_init_tab_workers(struct controller *dp);

    
void controller_configure_signaux(void);
void controller_gestionnaire_signal(int numero, 
            siginfo_t *info, void*data);
void controller_kill_worker(controller *dp, int signal);
void controller_fork_worker(controller *dp, int position);

    
/* FONCTIONS STATIQUES (POUR INFO)
statis int controller_init_worker(controller *dp, int queue_id,
    int position);
static int controller_get_loglevel(controller *dp, config_t *cfg)
static int controller_get_logs_dir(controller *dp, config_t *cfg)
static int controller_get_log_general_prefix(
        controller *dp, config_t *cfg)
static int controller_get_log_write_prefix(
    controller *dp, config_t *cfg)
static int controller_get_rangefile(controller *dp, config_t *cfg);
static int controller_get_dnsentryfile(controller *dp, config_t *cfg);
static void controller_get_nbworkers(controller *dp, config_t *cfg);
static int controller_get_queue_id(controller *dp, config_t *cfg);
static void controller_fork_worker(controller *dp, int position);
*/

#endif
