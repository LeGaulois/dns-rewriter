#ifndef WORKERS_H_INCLUDED
#define WORKERS_H_INCLUDED


#define MODE_QUERY 0
#define MODE_RESPONSE 1
#define MODE_ALL 2
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
    unsigned int    running:1;
    char            *shm_name;
    
    struct stats           st;    
};


void worker_main(worker *wk);
worker* worker_duplicate(worker *wk);
void worker_configure_signaux(void);
void worker_gestionnaire_signal(int numero, 
            siginfo_t *info, void*data);
void worker_cleanup(void);
#endif
