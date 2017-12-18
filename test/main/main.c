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
#include "controller.h"
#include <sys/types.h>
#include <inttypes.h>
#include "ntree_binary.h"
#include "hash.h"
#include "dns_translation.h"
#include "gestiondroits.h"


SLOGL_level programLevel = SLOGL_LVL_DEBUG;
worker **TABWORKERS;
ntree_root* ROOT;
hashtable *HASHTABLE;
hashtable *HASHTABLE_Q;
hashtable *HASHTABLE_R;
controller *CONTROLLER;
extern worker* ME; 


int free_datanode(void *data){
    free(data);
    return 1;
}


int main(int argc, char *argv[]){

    char *options = "f:h";
    int option;
    int i;
    int max = 0;
    worker *wk = NULL;
    
    opterr = 0;
    struct controller *ctrl = controller_init();
    
    if (ctrl==NULL){
        fprintf(stderr,"Erreur d'allocation du controller");
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
                free(ctrl->parameters_file);
                ctrl->parameters_file = strndup(optarg, strlen(optarg));
                break;
            case '?':
                fprintf(stderr,"Option %c non prise en charge\n", optopt);
        }
    }
    
    if(controller_complete_from_file(ctrl) ==0){
        SLOGL_vprint(SLOGL_LVL_INFO,"[controller] import OK");
    }
    else{
        SLOGL_vprint(SLOGL_LVL_ERROR,"[controller] Erreur durant l'import");
        controller_free(&ctrl,1);
        SLOGL_quit();
        return EXIT_FAILURE;
    }
    
    if(controller_set_securite(ctrl) != 0){
        controller_free(&ctrl,1);
        exit(1);
    }

    /**
     * On initie:
     * - la hashtable contenant les règles de réécriture
     *   DNS
     * - l'arbre binaire pour la concordance IP client/POP
     */
    ROOT = ntree_root_init_from_file(ctrl->range_file, &free_datanode);
    HASHTABLE = hashtable_init_from_file(128,&dns_translation_free,
     &dns_translation_compare_query ,ctrl->dnsentry_file, HT_NORMAL_FILE);
     
    HASHTABLE_Q = HASHTABLE;
    
    HASHTABLE_R = hashtable_init_from_file(128,&dns_translation_free,
&dns_translation_compare_query, ctrl->dnsentry_file, HT_INVERT_FILE);
    
    
    controller_init_tab_workers(ctrl);
    CONTROLLER = ctrl;
    controller_configure_signaux();
    
    /**
     * Variable globale utilisée par chaque worker
     */
    ME=NULL;
    for (i=0; i<ctrl->nb_workers*2;i++){
        controller_fork_worker(ctrl, i);
    }
    
    
    max = ctrl->nb_workers*2;
    
    /**
     * Boucle d'attente passive
     */
    while(ctrl->running_worker!=0){
        pause();
        
        /*
         * On verifie si le signal reçu necessite
         * le redemarrage de certains workers
         */
        for(i=0; i<max;i++){
            wk = *(ctrl->workerstab+i);
            
            if(wk->operation_pending & RESTART_BY_CONTROLLER){
                controller_restart_worker(CONTROLLER, wk->pid);
            }
        }
        
    }
    

    controller_free(&ctrl,1);
    SLOGL_quit();
    ntree_root_free(&ROOT);
    hashtable_free(&HASHTABLE);
    return EXIT_SUCCESS;
    
}
