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
#include <errno.h>


/*
 * Variables externes globales
 */
extern ntree_root *ROOT;
extern hashtable *HASHTABLE;
extern hashtable *HASHTABLE_Q;
extern hashtable *HASHTABLE_R;
extern interceptor *INTERCEPTOR;
worker *ME;



/**
 * WORKER MAIN
 * Fonction de travail du worker.
 * Lors de la fin de la tâche à effectuer, la fonction
 * doit terminer le processus.
 */
void worker_main(worker *wk){
    int ret;
    ME=wk;
    
    atexit(worker_cleanup);
    ret = worker_configure_signaux();
    
    if(ret!=0){
        wk->status = ERROR;
        exit(wk->status);
    }
    
    wk->status = OK;
    wk->operation_pending = RUNNING;
    
    /**
     * On ferme tous les descripteurs 
     * de fichier standarts (stderr, stdout, stdin)
     */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    ret = interceptor_worker(wk->nfqueue_id);

    if(ret!=0) wk->status = ERROR;
    
    
    wk->operation_pending |= SELF_STOP;
    exit(wk->status);
}


/*
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
}*/


/**
 * WORKER GESTIONNAIRE SIGNAL
 * Handlers pour les différents signaux.
 */
void worker_gestionnaire_signal(int numero, 
            siginfo_t *info, void*data)
{
    switch(numero){
        case SIGTERM:
            if(info->si_pid == ME->ppid){
                SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Le controller nous stoppe.", ME->number);
                exit(1);
            }
            break; 
        case SIGINT:
            if(info->si_pid == ME->ppid){
                SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] \
Le controller nous stoppe.", ME->number);
                exit(1);
            }
            break;
        default:
            SLOGL_vprint(SLOGL_LVL_INFO,"[worker %d] Reception du signal non géré %d. Aucune action", ME->number, numero);
            break;
    }
      
}


/**
 * WORKER CONFIGURE SIGNAUX
 * Configuration des handler pour les différents signaux.
 *
 * Valeurs de retour
 * 0  -> SUCCESS
 * -1 -> ERROR
 */
int worker_configure_signaux(void){
    struct sigaction action;
    action.sa_sigaction = worker_gestionnaire_signal;
    sigemptyset( &(action.sa_mask));
     
    if ( sigfillset( &(action.sa_mask)) == -1){
         SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur d'instanciation du masque des signaux: %s",
         ME->number, strerror(errno));
         return -1;
    }
    
    action.sa_flags = SA_RESTART | SA_SIGINFO;
    
    if ( sigaction(SIGINT, &action, NULL) != 0 ){
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur d'association du handler du signal SIGINT: %s",
 ME->number, strerror(errno));
        return -1;
    }
    if ( sigaction(SIGTERM, &action, NULL) != 0 ){
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] \
Erreur d'association du handler du signal SIGTERM: %s",
 ME->number, strerror(errno));
        return -1;
    }
    
    return 0;
}


/**
 * WORKER CLEANUP
 * Fonction de libration automatiques des ressources
 * à l'arrêt du worker
 */
void worker_cleanup(void){
    ME->operation_pending = ME->operation_pending & ~RUNNING;
    shm_unlink(ME->shm_name);
    free(ME->shm_name);
    SLOGL_quit();
    
    ntree_root_free(&ROOT);
    hashtable_free(&HASHTABLE_Q);
    hashtable_free(&HASHTABLE_R);
    interceptor_free(INTERCEPTOR);
}
