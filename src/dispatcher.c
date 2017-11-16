#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h> 
#include <libconfig.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include "configfile.h"
#include "logger.h"
#include "workers.h"
#include "dispatcher.h"


/*
 * Variables globales externes
 */
extern SLOGL_level programLevel;
extern dispatcher *DISPATCHER;

/*
 * Fcontions statiques
 */
 static int dispatcher_init_worker(dispatcher *dp, int queue_id,
    int position);
static int dispatcher_get_loglevel(dispatcher *dp, config_t *cfg);
static int dispatcher_get_logs_dir(dispatcher *dp, config_t *cfg);
static int dispatcher_get_log_general_prefix(
        dispatcher *dp, config_t *cfg);
static int dispatcher_get_log_write_prefix(
    dispatcher *dp, config_t *cfg);
static int dispatcher_get_rangefile(dispatcher *dp, config_t *cfg);
static int dispatcher_get_dnsentryfile(dispatcher *dp, config_t *cfg);
static void dispatcher_get_nbworkers(dispatcher *dp, config_t *cfg);
static int dispatcher_get_queue_id(dispatcher *dp, config_t *cfg);


/**
 * DISPATCHER_COMPLETE_FROM_FILE
 * Permet de remplir la struct dispatcher @dp
 * avec le contenu du fichier contenue dans la struct
 * @dp->parameters_file
 *
 * Valeurs de retour:
 * 0 -> SUCCESS
 * -1 sinon
 */
int dispatcher_complete_from_file(dispatcher *dp)
{
    config_t cfg;    
    if (configfile_init(&cfg, dp->parameters_file) !=0) goto error;
    if (configfile_read(&cfg, dp->parameters_file) !=0) goto destroy;
    
    if (dispatcher_get_loglevel(dp,&cfg) !=0 ) goto destroy;
    if (dispatcher_get_logs_dir(dp, &cfg) !=0 ) goto destroy;
    if (dispatcher_get_log_general_prefix(dp, &cfg) !=0 ) goto destroy;
    if (dispatcher_get_log_write_prefix(dp, &cfg) !=0 ) goto destroy;
    if (dispatcher_get_rangefile(dp, &cfg) !=0 ) goto destroy;
    if (dispatcher_get_dnsentryfile(dp, &cfg) !=0 ) goto destroy;
    dispatcher_get_nbworkers(dp, &cfg);

    if (dispatcher_get_queue_id(dp, &cfg) !=0 ) goto destroy;
    
    dp->workerstab = calloc(dp->nb_workers*2, sizeof(worker*));
    
    if (dp->workerstab==NULL) goto destroy;
    memset(dp->workerstab, 0, dp->nb_workers*2*sizeof(worker*));
    
    dp->fd_shared = calloc(dp->nb_workers*2, sizeof(int));
    
    if (dp->fd_shared==NULL) goto destroy;

    config_destroy(&cfg);
    return 0;
    
    destroy:
        config_destroy(&cfg);
        goto error;
        
    error:
        return -1;
    
}


/**
 * DISPATCHER_INIT
 * Initie une struct dispatcher
 *
 * Valeur de retour
 * NULL -> ECHEC
 * pointeur sur une nouvelle struct dispatcher
 */
struct dispatcher* dispatcher_init(){
    struct dispatcher *dp = NULL;
    
    dp = calloc(1,sizeof(struct dispatcher));
    
    if (dp==NULL) return NULL;
    memset(dp, 0 , sizeof(struct dispatcher));
    dp->parameters_file = strndup("/etc/dns-rewriter/dns-rewriter.conf",35);
    
    return dp;
}


/**
 * DISPATCHER_FREE
 * Supprime une structure dispatcher
 *
 * Parametres
 * @dp: adresse du pointeur sur une struct dispatcher
 * @close_shm_link: indique si le segment de mémoire partagée
 *      doit etre supprimer
 *
 */
void dispatcher_free(dispatcher **dp, int close_shm_link){
    int i;
    worker *wk = NULL;
    
    if(*dp==NULL) return;
    
    free((*dp)->parameters_file);
    free((*dp)->range_file);
    free((*dp)->dnsentry_file);
    free((*dp)->logs_dir);
    free((*dp)->log_general_prefix);
    free((*dp)->log_rewrite_prefix);
    dispatcher_free_all_worker_except(*dp,NULL);
    free((*dp)->workerstab);
    free((*dp)->fd_shared);
    free(*dp); 
}


/**
 * DISPATCHER_FREE_ALL_WORKER_EXCEPT
 * Supprime tous les workers d'une structure dispatcher
 * à l'exception du worker @c
 *
 * Parametres
 * @dp: pointeur sur la structure dispatcher
 * @c: pointeur sur le worker à conserver
 */
void dispatcher_free_all_worker_except(dispatcher *dp, worker *c){
    int i, max;
    worker *wk;
    
    if(dp==NULL) return;
    max = dp->nb_workers * 2;
    
    for(i=0; i<max;i++){
        wk =  (worker*)( *(dp->workerstab + i) );
        if ((wk==NULL)||(wk==c)){
            continue;
        }
        shm_unlink(wk->shm_name);
        free(wk->shm_name);
        close(*(dp)->fd_shared+i);
        dp->running_worker--;
        *(dp->workerstab + i) = NULL; 
    }
    
}


/**
 * DISPATCHER_GET_LOGLEVEL
 * Rempli le champ log_level de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_loglevel(dispatcher *dp, config_t *cfg){
    int dlevel;
    
    if(config_lookup_int(cfg, "LOGS.debug_level", &dlevel)){
        if( (dlevel>=0)&&(dlevel<8) ){
            dp->debug_level = (short unsigned int)(dlevel);
        }
        else return -1;
    }
    else {
        dp->debug_level = SLOGL_LVL_WARNING;
    }
    
    programLevel = dp->debug_level;
    
    return 0;
}


/**
 * DISPATCHER_GET_LOGS_DIR
 * Rempli le champ logs_dir de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_logs_dir(dispatcher *dp, config_t *cfg){
    size_t len_str =0;
    const char *str_tmp = NULL;
    
    if(config_lookup_string(cfg, "LOGS.logs_dir", &str_tmp)){
        len_str = strlen(str_tmp)+1;

         if (access(str_tmp, R_OK)!=0){
            fprintf(stderr,
        "Le dossier de logs %s n'est pas accessible en ecriture.",
         str_tmp);
         
            return -1;
        }
        
        dp->logs_dir = calloc(len_str, sizeof(char));
        strncpy( dp->logs_dir, str_tmp, len_str-1 );
        
        //SLOGL_init(dp->logs_dir);
        return 0;
    }

    return -1;
}


/**
 * DISPATCHER_GET_LOG_GENERAL_PREFIX
 * Rempli le champ log_general_prefix de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_log_general_prefix(
        dispatcher *dp, config_t *cfg)
{
    size_t len_str =0;
    const char *str_tmp = NULL;
    char *tmp =NULL;
    char test;
    
    if(config_lookup_string(cfg, "LOGS.log_general_prefix", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        dp->log_general_prefix = calloc(len_str, sizeof(char));
        strncpy( dp->log_general_prefix, str_tmp, len_str-1 );
        
        len_str = strlen(dp->log_general_prefix) + strlen(dp->logs_dir)+1;
        
        test = dp->logs_dir[strlen(dp->logs_dir)-1]; 
        if( test !='/') len_str++;
        tmp = calloc(len_str,sizeof(char));
        
        if (tmp==NULL) return -1;
        if(test !='/'){
            snprintf(tmp,len_str,"%s%s",
                dp->logs_dir,dp->log_general_prefix);
        }
        else{
            snprintf(tmp,len_str,"%s%s",
                dp->logs_dir,dp->log_general_prefix);
        }
        SLOGL_init(tmp);
        
        free(tmp);
        return 0;
    }

    return -1;
}


/**
 * DISPATCHER_GET_LOG_WRITE_PREFIX
 * Rempli le champ general_log de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_log_write_prefix(
    dispatcher *dp, config_t *cfg)
{
    size_t len_str =0;
    const char *str_tmp = NULL;
    
    if(config_lookup_string(cfg, "LOGS.log_rewrite_prefix", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        dp->log_rewrite_prefix = calloc(len_str, sizeof(char));
        strncpy( dp->log_rewrite_prefix, str_tmp, len_str-1 );

        return 0;
    }

    return -1;
}


/**
 * DISPATCHER_GET_RANGEFILE
 * Rempli le champ log_level de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_rangefile(dispatcher *dp, config_t *cfg){
    const char *str_tmp = NULL;
    size_t len_str =0;
    
    if(config_lookup_string(cfg, "GENERAL.range_file", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        if (access(str_tmp, R_OK)!=0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
        "Le fichier %s n'est pas accessible en lecture.",
         str_tmp);
            return -1;
        }
        dp->range_file= calloc(len_str, sizeof(char));
        strncpy( dp->range_file, str_tmp, len_str-1 );
        
        SLOGL_vprint(SLOGL_LVL_INFO,
        "%s: range file -> %s", config_error_file(cfg), str_tmp);
        return 0;
    }
    SLOGL_vprint(SLOGL_LVL_ERROR,
        "%s: aucun fichier de zone defini",
         config_error_file(cfg));
    return -1;
}


/**
 * DISPATCHER_GET_DNS_ENTRY_FILE
 * Rempli le champ dnsentry_file de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_dnsentryfile(dispatcher *dp, config_t *cfg){
    const char *str_tmp = NULL;
    size_t len_str =0;
    
    if(config_lookup_string(cfg, "GENERAL.dnsentry_file", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        if (access(str_tmp, R_OK)!=0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
        "Le fichier %s n'est pas accessible en lecture.",
         str_tmp);
            return -1;
        }
        
        dp->dnsentry_file= calloc(len_str, sizeof(char));
        strncpy( dp->dnsentry_file, str_tmp, len_str-1 );
        
        SLOGL_vprint(SLOGL_LVL_INFO,
        "%s: fichier entrées DNS -> %s", config_error_file(cfg), str_tmp);
        return 0;
    }
    SLOGL_vprint(SLOGL_LVL_ERROR,
        "%s: aucun fichier de d'entrées DNS defini",
         config_error_file(cfg));
    return -1;
}


/**
 * DISPATCHER_GET_NBWORKERS
 * Rempli le champ nb_workers de la structure
 * dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static void dispatcher_get_nbworkers(dispatcher *dp, config_t *cfg){
    int nbworkers;
    
    if(config_lookup_int(cfg, "WORKER.nb_workers", &nbworkers)){
        if( (nbworkers>=0)&&(nbworkers<=MAX_WORKERS) ){
            dp->nb_workers = nbworkers;
            SLOGL_vprint(SLOGL_LVL_INFO,
        "%s: utilisation de %d workers (%d par file)",
         config_error_file(cfg), nbworkers*2, nbworkers);
        }
        else {
            dp->nb_workers = 1;
            SLOGL_vprint(SLOGL_LVL_ERROR,
        "%s: nombre de workers indique invalide (%d). Utilisation de \
la valeur par default (1 par file)",
         config_error_file(cfg), nbworkers);
        }
    }
    else {
        dp->nb_workers = 1;
        SLOGL_vprint(SLOGL_LVL_ERROR,
        "%s: nombre de workers n'est pas indique. Utilisation de \
la valeur par default (1 par file)", config_error_file(cfg));
    }
    
    programLevel = dp->debug_level;
}


/**
 * DISPATCHER_GET_QUEUE_ID
 * Rempli les champ first_query_queue et first_response_queue 
 * de la structure dispatcher @dp à partir de @cfg
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @dispatcher_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_get_queue_id(dispatcher *dp, config_t *cfg){
    int id;
    
    if(config_lookup_int(cfg, "WORKER.first_query_queue", &id)){
        dp->first_query_queue = id;
        SLOGL_vprint(SLOGL_LVL_INFO,
"%s: utilisation des files %d à %d en entree",
         config_error_file(cfg), id, dp->nb_workers+id);
    }
    else {
        SLOGL_vprint(SLOGL_LVL_ERROR,
"%s: aucune ID de file nfqueue indiquee",
         config_error_file(cfg));
         return -1;
    }
    
    if(config_lookup_int(cfg, "WORKER.first_response_queue", &id)){
        dp->first_response_queue = id;
        SLOGL_vprint(SLOGL_LVL_INFO,
"%s: utilisation des files %d à %d en sortie",
         config_error_file(cfg), id, dp->nb_workers+id);
    }
    else {
        SLOGL_vprint(SLOGL_LVL_ERROR,
"%s: aucune ID de file nfqueue indiquee",
         config_error_file(cfg));
         return -1;
    }
    
    return 0;
    
}


/**
 * DISPATCHER_INIT_TAB_WORKERS
 * Initialise le tableau de pointeur de structure worker.
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
int dispatcher_init_tab_workers(struct dispatcher *dp){
    int i, queue_id;

      
    queue_id = dp->first_query_queue;
        
    for(i=0; i< dp->nb_workers*2 ; i++){
        
        if( dispatcher_init_worker(dp, queue_id, i)!=0){
            return -1;
        }
        
        if (i+1==dp->nb_workers) queue_id = dp->first_response_queue;
        else queue_id++;
    }
    
    return 0;
}


/**
 * DISPATCHER_INIT_WORKER
 * Initialise un nouveau worker dans le tableau workerstab
 * de la structure @dp
 *
 * Parametres
 * @dp: pointeur sur une structure dispatcher
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int dispatcher_init_worker(dispatcher *dp, int queue_id,
    int position)
{
    char *shm_name = NULL;
    int fd; 
    worker *wk = NULL;
        
    fd = *((dp->fd_shared) + position);
    shm_name = calloc(25, sizeof(char));
    snprintf(shm_name, 25,"dns-rewriter_worker_%d", position);
    fprintf(stderr,"QID: %d\n", queue_id);
    if ( (fd = shm_open(shm_name, O_RDWR | O_CREAT, 0600)) == -1){
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] Erreur lors de \
l'ouverture de la memoire partage %s: %s", shm_name, strerror(errno));
            
        return -1;
    }
        
    if(ftruncate(fd, sizeof(worker)) !=0){
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] Erreur lors du \
dimensionnement de la memoire partage %s: %s", shm_name, strerror(errno));
        return -1;
    }
        
    wk = (worker*)(mmap(NULL, sizeof(worker), PROT_READ | PROT_WRITE,MAP_SHARED,fd, 0));
    wk->shm_name = shm_name;
         
    if( wk == MAP_FAILED ){
        SLOGL_vprint(SLOGL_LVL_ERROR,"[worker %d] Erreur lors de la \
projection en memoire: %s", strerror(errno));
        return -1;
    }
        
    *(dp->workerstab + position) = wk;
    dp->running_worker += 1;
    wk->nfqueue_id = queue_id;
    
    return 0;
}


/**
 * DISPATCHER_CONFIGURE_SIGNAUX
 * Configure la gestion des signaux sur le dispatcher
 *
 */
void dispatcher_configure_signaux(void){
    int i;
    
    struct sigaction action;
    action.sa_handler = dispatcher_gestionnaire_signal;
    sigemptyset( &(action.sa_mask));
    
    for(i=0; i<NSIG; i++){
        sigaddset( &(action.sa_mask), i);
    }
    
    action.sa_flags = SA_NOCLDSTOP | SA_RESTART | SA_SIGINFO;
    
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
}


/**
 * DISPATCHER_GESTIONNAIRE_SIGNAL
 * Handler pour les signaux
 */
void dispatcher_gestionnaire_signal(int numero, 
            siginfo_t *info, void *data)
{
    switch(numero){
        case SIGCHLD:
            DISPATCHER->running_worker--;
            if(info->si_status != EXIT_SUCCESS){
                //TODO: relancer worker
                SLOGL_vprint(SLOGL_LVL_ERROR,"Terminaison  \
non sollicite du worker (pid=%d)",
             info->si_pid);
            } 
            break;
        case SIGINT:
            dispatcher_kill_worker(DISPATCHER);
            break;
        case SIGTERM:
            dispatcher_kill_worker(DISPATCHER);
            break;
        default:
            break;
    }
}


/**
 * DISPATCHER_KILL_WORKER
 * Envoie le signal SIGTERM à tous les workers
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
void dispatcher_kill_worker(dispatcher *dp){
    int max, i, ret;
    worker *wk = NULL;
    
    if (dp==NULL) return;    
    max = dp->nb_workers *2;
    
    for(i=0; i<max; i++){
        wk = *(dp->workerstab + i);
        
        if (wk==NULL) continue;
        ret = kill(wk->pid, SIGTERM);
        
        if(ret==0){
            SLOGL_vprint(SLOGL_LVL_INFO,"Envoie du signal SIGTERM \
au worker %d (pid=%d)",i, wk->pid);
        }
        else{
            SLOGL_vprint(SLOGL_LVL_ERROR,"Erreur lors de l'envoie \
du signal SIGTERM au worker %d (pid=%d): %s",
             i, wk->pid, strerror(errno));
        }
        wk = NULL;
    }
}
