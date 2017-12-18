#ifndef WORKERS_H_INCLUDED
#define WORKERS_H_INCLUDED

#define OK 0
#define ERROR 1
#define CRITICAL_ERROR 2


#include <signal.h>


enum {
    RESTART_BY_CONTROLLER = 1<<0,
    STOP_BY_CONTROLLER = 1<<1,
    SELF_STOP = 1<<2,
    RUNNING = 1<<3
};


/*
* WORKER
* Structure permettant de stocker toutes les informations
* sur le worker, ses ressources et ses stats.
*
* [INFOS]
*   - pid: pid du processus. Sera utile pour le père pour savoir
*       lequel de ses fils s'est termine --> SIGCHILD
*   - ppid: processus du pere  pour l'envoie de signaux
*
* [STATS]
*   Différentes stats sur le traitement de paquest DNS
*   
* 
*
*/
typedef struct worker worker;
typedef struct stats stats;

struct stats {
    long long       nb_requetes_recues;
    long long       nb_requetes_rewrite;
    long long       nb_requetes_pass;
    long long       nb_requetes_block;
    long long       nb_requetes_silent;
};

struct worker {
    pid_t           pid;
    pid_t           ppid;
    int             nfqueue_id;
    int             number;
    int             status;
    int             operation_pending;
    char            *shm_name;
    
    struct stats           st;    
};


void worker_main(worker *wk);
//worker* worker_duplicate(worker *wk);
int worker_configure_signaux(void);
void worker_gestionnaire_signal(int numero, 
            siginfo_t *info, void*data);
void worker_cleanup(void);
#endif
