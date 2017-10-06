#ifndef WORKERS_H_INCLUDED
#define WORKERS_H_INCLUDED


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
 
struct worker {
    pid_t           pid;
    pid_t           ppid;
    int             nfqueue_id;
    
    long long       nb_requetes_recues;
    long long       nb_requetes_rewrite;
    long long       nb_requetes_pass;
    long long       nb_requetes_block;
    long long       nb_requetes_silent;
    
    list            session_dns_record;
    int             fd_tree_binary;
    ntree_binary    root_tree; 
    int             fd_dns_entry;  
    list            *dnsentries;
};

#endif
