#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include "logger.h"
#include "workers.h"
#include "dispatcher.h"
#include <sys/types.h>
#include <inttypes.h>
#include "ntree_binary.h"
#include "hash.h"
#include "dns_translation.h"


SLOGL_level programLevel = SLOGL_LVL_DEBUG;
worker **TABWORKERS;
ntree_root* ROOT;
hashtable *HASHTABLE;
dispatcher *DISPATCHER;


int free_datanode(void *data){
    free(data);
    return 1;
}


int main(int argc, char *argv[]){

    char *options = "f:h";
    int option;
    int i;
    pid_t pid;
    worker *wk = NULL;
    
    opterr = 0;
    struct dispatcher *dp = dispatcher_init();
    
    if (dp==NULL){
        fprintf(stderr,"Erreur d'allocation '");
        return EXIT_FAILURE;
    }
    
    
    while((option = getopt(argc, argv, options)) != -1){
        switch(option){
            case 'h':
                fprintf(stdout, "Utilisation: %s [options]\n\n \
                avec les options parmis: \n \
                -h: affiche le message actuel \n \
                -f: specifie le fichier de configuration a utiliser \n \
                (etc/dns-rewriter/dns-rewriter.conf par défaut)\n",
                argv[0]);
                
                return EXIT_SUCCESS;
            case 'f':
                fprintf(stdout,"Chargement du fichier de configuration \
                %s\n", optarg);
                free(dp->parameters_file);
                dp->parameters_file = strndup(optarg, strlen(optarg));
                break;
            case '?':
                fprintf(stderr,"Option %c non prise en charge\n", optopt);
        }
    }
    
    if(dispatcher_complete_from_file(dp) ==0){
        SLOGL_vprint(SLOGL_LVL_INFO,"import OK");
    }
    else{
        SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur durant l'import");
        dispatcher_free(&dp,1);
        SLOGL_quit();
        return EXIT_FAILURE;
    }
    
    
    /*
     * Initialisation des outils statiques 
     * (arbre binaire + hashtable)
     * TODO: Procedure de reload
     * 1) Envoie du signal SIGUSR1 ou SIGUSR2 au dispatcher
     * 2) Dispatcher supprime les variables globales ROOT et HASHTABLE
     * 3) On kill chaque worker puis on le recree 
     *    (mini interruption de service si pas de HA)
     */
    ROOT = ntree_root_init_from_file(dp->range_file, &free_datanode);
    HASHTABLE = hashtable_init_from_file(128,&dns_translation_free,
     &dns_translation_compare_query ,dp->dnsentry_file);
    
    
    dispatcher_init_tab_workers(dp);
    DISPATCHER = dp;
    dispatcher_configure_signaux();
    
    for (i=0; i<dp->nb_workers*2;i++){
        wk = *(dp->workerstab + i);
        
        pid = fork();
        
        switch (pid){
            case 0:
                wk->pid = getpid();
                wk->ppid = getppid();
                
                /*
                 * A ce niveau là le fork a reussi (on est un worker)
                 * On peut donc supprimer la structure DISPATCHER
                 * (heritée du père).
                 * On prend garde à ne pas se supprimer soit même
                 * en se dereferencer de la struct dispatcher
                 */
                dispatcher_free_all_worker_except(dp,wk);
                *(dp->workerstab + i) = NULL;
                dispatcher_free(&dp,0);
                DISPATCHER = NULL;
                
                /*
                 * On execute notre boucle de travail qui devra 
                 * faire un exit(), pas de retour dans le main
                 */
                worker_main(wk);
            case -1:
                SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur lors du fork: %s",
                strerror(errno));
            default:
                SLOGL_vprint(SLOGL_LVL_INFO,"Creation d'un nouveau worker \
                pid %d",pid);
                wk->pid = pid;
        }
    }
    
    
    /*
     * Boucle Infinie
     * On attend que tous les fils aient finis leurs jobs 
     * Aucune utilisation de CPU, on dort jusqu'à la réception d'un signal
     * à chaque sortie du handler, on verifiera si au moins 1 des workers
     * est tjrs actif.
     * TODO: ajouter la gestion
     *  - des reload de config
     *  - redemarrage d'un worker en cas d'erreur
     */
    while(dp->running_worker!=0){
        pause();
    }
    fprintf(stderr,"Fini\n");
    

    dispatcher_free(&dp,1);
    SLOGL_quit();
    ntree_root_free(&ROOT);
    hashtable_free(&HASHTABLE);
    return EXIT_SUCCESS;
    
}
