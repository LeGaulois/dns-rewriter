#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include "logger.h"
#include <string.h>
#include <inttypes.h>
#include "ntree_binary.h"
#include "hash.h"
#include "dns_translation.h"
#include "workers.h"
#include "interceptor.h"


/*
 * Variables externes globales
 */
extern ntree_root *ROOT;
extern hashtable *HASHTABLE;
extern interceptor *INTERCEPTOR;
worker *ME;



void worker_main(worker *wk){

    ME=wk;
    worker_configure_signaux();
    atexit(worker_cleanup);
    
    
    
    
    
    /*
     * A supprimer, juste quelques lignes de test 
     */
     fprintf(stderr,"Hello, je suis %s avec le pid %d et mon pere est %d, queue id=%d\n",
    wk->shm_name, wk->pid, wk->ppid, wk->nfqueue_id);
    wk->st.nb_requetes_recues = 100;
    
    
    /*
     * A COMPLETER
     * J'ai pris l'exemple de la libmnl
     */
    interceptor_worker(wk->nfqueue_id);
    /**/
    
    
    wk->st.nb_requetes_recues += wk->pid;
    SLOGL_vprint(SLOGL_LVL_INFO,"Test");
    
    exit(EXIT_SUCCESS);
}


worker* worker_duplicate(worker *wk){
    worker* new = NULL;
    char *myshm_name = NULL;
        
    new = calloc(1, sizeof(worker));
    
    if (new==NULL) return NULL;
    myshm_name = strndup(wk->shm_name, strlen(wk->shm_name));
    
    if (myshm_name==NULL){
        free(new);
        return NULL;
    }
    
    memcpy(new, wk, sizeof(worker));
    new->shm_name = myshm_name;
    
    return new;
}


void worker_configure_signaux(void){
    int i;
    
    struct sigaction action;
    action.sa_handler = worker_gestionnaire_signal;
    sigemptyset( &(action.sa_mask));
    
    for(i=0; i<NSIG; i++){
        sigaddset( &(action.sa_mask), i);
    }
    
    action.sa_flags = SA_NOCLDSTOP | SA_RESTART | SA_SIGINFO;
    
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}


void worker_gestionnaire_signal(int numero, 
            siginfo_t *info, void*data)
{
    switch(numero){
        case SIGTERM:
            if(info->si_pid == ME->ppid){
                SLOGL_vprint(SLOGL_LVL_INFO,"Dispatcher (pid=%d) \
nous a envoye le signal de fin", ME->ppid);
                exit(EXIT_SUCCESS);
            }
            break; 
        case SIGINT:
            if(info->si_pid == ME->ppid){
                SLOGL_vprint(SLOGL_LVL_INFO,"Dispatcher (pid=%d) \
nous a envoye le signal de fin", ME->ppid);
                exit(EXIT_SUCCESS);
            }
            break;
        default:
            break;
    }
      
}


void worker_cleanup(void){
    shm_unlink(ME->shm_name);
    free(ME->shm_name);
    SLOGL_quit();
    
    ntree_root_free(&ROOT);
    hashtable_free(&HASHTABLE);
    interceptor_free(INTERCEPTOR);
}
