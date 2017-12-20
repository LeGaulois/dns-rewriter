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
#include <sys/types.h>
#include <sys/wait.h>

#include "gestiondroits.h"
#include "workers.h"
#include "configfile.h"
#include "logger.h"
#include "workers.h"
#include "controller.h"


/*
 * Variables globales externes
 */
extern SLOGL_level programLevel;
extern controller *CONTROLLER;
extern worker* ME;

/*
 * Fonctions statiques
 */
 static int controller_init_worker(controller *ctrl, int queue_id,
    int position);
static int controller_get_loglevel(controller *ctrl, config_t *cfg);
static int controller_get_logs_dir(controller *ctrl, config_t *cfg);
static int controller_get_log_general_prefix(
        controller *ctrl, config_t *cfg);
static int controller_get_log_write_prefix(
    controller *ctrl, config_t *cfg);
static int controller_get_rangefile(controller *ctrl, config_t *cfg);
static int controller_get_dnsentryfile(controller *ctrl, config_t *cfg);
static void controller_get_nbworkers(controller *ctrl, config_t *cfg);
static int controller_get_queue_id(controller *ctrl, config_t *cfg);
static int controller_get_username(controller *ctrl, config_t *cfg);
static int controller_get_groupname(controller *ctrl, config_t *cfg);
static void controller_stop_worker(controller *ctrl, int position, int signal);


/**
 * CONTROLLER_COMPLETE_FROM_FILE
 * Permet de remplir la struct controller @ctrl
 * avec le contenu du fichier contenue dans la struct
 * @ctrl->parameters_file
 *
 * Valeurs de retour:
 * 0 -> SUCCESS
 * -1 sinon
 */
int controller_complete_from_file(controller *ctrl)
{
    config_t cfg;    
    if (configfile_init(&cfg, ctrl->parameters_file) !=0) goto error;
    if (configfile_read(&cfg, ctrl->parameters_file) !=0) goto destroy;
    
    if (controller_get_loglevel(ctrl,&cfg) !=0 ) goto destroy;
    if (controller_get_logs_dir(ctrl, &cfg) !=0 ) goto destroy;
    if (controller_get_log_general_prefix(ctrl, &cfg) !=0 ) goto destroy;
    if (controller_get_log_write_prefix(ctrl, &cfg) !=0 ) goto destroy;
    if (controller_get_rangefile(ctrl, &cfg) !=0 ) goto destroy;
    if (controller_get_dnsentryfile(ctrl, &cfg) !=0 ) goto destroy;
    controller_get_username(ctrl, &cfg);
    controller_get_groupname(ctrl, &cfg);
    controller_get_nbworkers(ctrl, &cfg);

    if (controller_get_queue_id(ctrl, &cfg) !=0 ) goto destroy;
    
    ctrl->workerstab = calloc(ctrl->nb_workers*2, sizeof(worker*));
    
    if (ctrl->workerstab==NULL) goto destroy;
    memset(ctrl->workerstab, 0, ctrl->nb_workers*2*sizeof(worker*));
    

    config_destroy(&cfg);
    return 0;
    
    destroy:
        config_destroy(&cfg);
        goto error;
        
    error:
        return -1;
    
}


/**
 * CONTROLLER_INIT
 * Initie une struct controller
 *
 * Valeur de retour
 * NULL -> ECHEC
 * pointeur sur une nouvelle struct controller
 */
struct controller* controller_init(){
    struct controller *ctrl = NULL;
    
    ctrl = calloc(1,sizeof(struct controller));
    
    if (ctrl==NULL) return NULL;
    memset(ctrl, 0 , sizeof(struct controller));
    ctrl->parameters_file = strndup("/etc/dns-rewriter/dns-rewriter.conf",35);
    
    return ctrl;
}


/**
 * CONTROLLER_FREE
 * Supprime une structure controller
 *
 * Parametres
 * @ctrl: adresse du pointeur sur une struct controller
 * @close_shm_link: indique si le segment de mémoire partagée
 *      doit etre supprimer
 *
 */
void controller_free(controller **ctrl, int close_shm_link){
    
    if(*ctrl==NULL) return;
    
    free((*ctrl)->parameters_file);
    free((*ctrl)->range_file);
    free((*ctrl)->dnsentry_file);
    free((*ctrl)->logs_dir);
    free((*ctrl)->log_general_prefix);
    free((*ctrl)->log_rewrite_prefix);
    free((*ctrl)->username);
    free((*ctrl)->groupname);
    controller_free_all_worker_except(*ctrl,NULL);
    free((*ctrl)->workerstab);
    free(*ctrl); 
}


/**
 * CONTROLLER_FREE_ALL_WORKER_EXCEPT
 * Supprime tous les workers d'une structure controller
 * à l'exception du worker @c
 *
 * Parametres
 * @ctrl: pointeur sur la structure controller
 * @c: pointeur sur le worker à conserver
 */
void controller_free_all_worker_except(controller *ctrl, worker *c){
    int i, max;
    worker *wk;
    
    if(ctrl==NULL) return;
    max = ctrl->nb_workers * 2;
    
    for(i=0; i<max;i++){
        wk =  (worker*)( *(ctrl->workerstab + i) );
        if ((wk==NULL)||(wk==c)){
            continue;
        }
        shm_unlink(wk->shm_name);
        free(wk->shm_name);
        ctrl->running_worker--;
        *(ctrl->workerstab + i) = NULL;
    }
    
}


/**
 * CONTROLLER_GET_LOGLEVEL
 * Rempli le champ log_level de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_loglevel(controller *ctrl, config_t *cfg){
    int dlevel;
    
    if(config_lookup_int(cfg, "LOGS.debug_level", &dlevel)){
        if( (dlevel>=0)&&(dlevel<8) ){
            ctrl->debug_level = (short unsigned int)(dlevel);
        }
        else return -1;
    }
    else {
        ctrl->debug_level = SLOGL_LVL_WARNING;
    }
    
    programLevel = ctrl->debug_level;
    
    return 0;
}


/**
 * CONTROLLER_GET_LOGS_DIR
 * Rempli le champ logs_dir de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_logs_dir(controller *ctrl, config_t *cfg){
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
        
        ctrl->logs_dir = calloc(len_str, sizeof(char));
        strncpy( ctrl->logs_dir, str_tmp, len_str-1 );
        
        //SLOGL_init(ctrl->logs_dir);
        return 0;
    }

    return -1;
}


/**
 * CONTROLLER_GET_LOG_GENERAL_PREFIX
 * Rempli le champ log_general_prefix de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_log_general_prefix(
        controller *ctrl, config_t *cfg)
{
    size_t len_str =0;
    const char *str_tmp = NULL;
    char *tmp =NULL;
    char test;
    
    if(config_lookup_string(cfg, "LOGS.log_general_prefix", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        ctrl->log_general_prefix = calloc(len_str, sizeof(char));
        strncpy( ctrl->log_general_prefix, str_tmp, len_str-1 );
        
        len_str = strlen(ctrl->log_general_prefix) + strlen(ctrl->logs_dir)+1;
        
        test = ctrl->logs_dir[strlen(ctrl->logs_dir)-1]; 
        if( test !='/') len_str++;
        tmp = calloc(len_str,sizeof(char));
        
        if (tmp==NULL) return -1;
        if(test !='/'){
            snprintf(tmp,len_str,"%s%s",
                ctrl->logs_dir,ctrl->log_general_prefix);
        }
        else{
            snprintf(tmp,len_str,"%s%s",
                ctrl->logs_dir,ctrl->log_general_prefix);
        }
        SLOGL_init(tmp);
        
        free(tmp);
        return 0;
    }

    return -1;
}


/**
 * CONTROLLER_GET_LOG_WRITE_PREFIX
 * Rempli le champ general_log de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_log_write_prefix(
    controller *ctrl, config_t *cfg)
{
    size_t len_str =0;
    const char *str_tmp = NULL;
    
    if(config_lookup_string(cfg, "LOGS.log_rewrite_prefix", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        ctrl->log_rewrite_prefix = calloc(len_str, sizeof(char));
        strncpy( ctrl->log_rewrite_prefix, str_tmp, len_str-1 );

        return 0;
    }

    return -1;
}


/**
 * CONTROLLER_GET_RANGEFILE
 * Rempli le champ log_level de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_rangefile(controller *ctrl, config_t *cfg){
    const char *str_tmp = NULL;
    size_t len_str =0;
    
    if(config_lookup_string(cfg, "GENERAL.range_file", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        if (access(str_tmp, R_OK)!=0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
        "[controller] Le fichier %s n'est pas accessible en lecture.",
         str_tmp);
            return -1;
        }
        ctrl->range_file= calloc(len_str, sizeof(char));
        strncpy( ctrl->range_file, str_tmp, len_str-1 );
        
        SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: range file -> %s",\
         config_error_file(cfg), str_tmp);
        return 0;
    }
    SLOGL_vprint(SLOGL_LVL_ERROR,
        "[controller] %s: aucun fichier de zone defini",
         config_error_file(cfg));
    return -1;
}


/**
 * CONTROLLER_GET_DNS_ENTRY_FILE
 * Rempli le champ dnsentry_file de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_dnsentryfile(controller *ctrl, config_t *cfg){
    const char *str_tmp = NULL;
    size_t len_str =0;
    
    if(config_lookup_string(cfg, "GENERAL.dnsentry_file", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        if (access(str_tmp, R_OK)!=0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
        "[controller] Le fichier %s n'est pas accessible en lecture.",str_tmp);
            return -1;
        }
        
        ctrl->dnsentry_file= calloc(len_str, sizeof(char));
        strncpy( ctrl->dnsentry_file, str_tmp, len_str-1 );
        
        SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: fichier entrées DNS -> %s",
         config_error_file(cfg), str_tmp);
        return 0;
    }
    SLOGL_vprint(SLOGL_LVL_ERROR,
        "[controller] %s: aucun fichier de d'entrées DNS defini",
         config_error_file(cfg));
    return -1;
}


/**
 * CONTROLLER_GET_NBWORKERS
 * Rempli le champ nb_workers de la structure
 * controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static void controller_get_nbworkers(controller *ctrl, config_t *cfg){
    int nbworkers;
    
    if(config_lookup_int(cfg, "WORKER.nb_workers", &nbworkers)){
        if( (nbworkers>=0)&&(nbworkers<=MAX_WORKERS) ){
            ctrl->nb_workers = nbworkers;
            SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: utilisation de %d workers (%d par file)",
        config_error_file(cfg), nbworkers*2, nbworkers);
        }
        else {
            ctrl->nb_workers = 1;
            SLOGL_vprint(SLOGL_LVL_ERROR,
        "[controller] %s: nombre de workers indique invalide \
(%d). Utilisation de la valeur par default (1 par file)",
         config_error_file(cfg), nbworkers);
        }
    }
    else {
        ctrl->nb_workers = 1;
        SLOGL_vprint(SLOGL_LVL_ERROR,
        "[controller] %s: nombre de workers n'est pas indique. \
Utilisation de la valeur par default (1 par file)",
        config_error_file(cfg));
    }
    
    programLevel = ctrl->debug_level;
}


/**
 * CONTROLLER_GET_QUEUE_ID
 * Rempli les champ first_query_queue et first_response_queue 
 * de la structure controller @ctrl à partir de @cfg
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_get_queue_id(controller *ctrl, config_t *cfg){
    int id;
    
    if(config_lookup_int(cfg, "WORKER.first_query_queue", &id)){
        ctrl->first_query_queue = id;
        SLOGL_vprint(SLOGL_LVL_INFO,
"[controller] %s: utilisation des files %d à %d en entree",
         config_error_file(cfg), id, ctrl->nb_workers+id);
    }
    else {
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] %s: aucune ID de file nfqueue indiquee",
         config_error_file(cfg));
         return -1;
    }
    
    if(config_lookup_int(cfg, "WORKER.first_response_queue", &id)){
        ctrl->first_response_queue = id;
        SLOGL_vprint(SLOGL_LVL_INFO,
"[controller] %s: utilisation des files %d à %d en sortie",
         config_error_file(cfg), id, ctrl->nb_workers+id);
    }
    else {
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] %s: aucune ID de file nfqueue indiquee",
         config_error_file(cfg));
         return -1;
    }
    
    return 0;
    
}


/**
 * CONTROLLER_GET_USERNAME
 * Récupére le nom de l'utilisateur qui aura la possesion
 * des différents processus. 
 * La fonction verifie que l'utilisateur existe
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> l'utilisateur n'existe pas
 */
static int controller_get_username(controller *ctrl, config_t *cfg){
    const char *str_tmp = NULL;
    size_t len_str =0;
    
    if(config_lookup_string(cfg, "SECURITY.username", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        if(convert_username_to_uid(str_tmp)<0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] %s: l'utilisateur %s n'existe pas sur le systeme.",
         config_error_file(cfg), str_tmp);
            return -1;
        }
        
        ctrl->username = calloc(len_str, sizeof(char));
        strncpy( ctrl->username, str_tmp, len_str-1 );
        
        SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: username -> %s",
         config_error_file(cfg), str_tmp);
        return 0;
    }
    SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: aucun utilisateur d'execution defini",
         config_error_file(cfg));
    return 0;
}


/**
 * CONTROLLER_GET_GROUPNAME
 * Récupére le nom du froupe qui aura la possesion
 * des différents processus. 
 * La fonction verifie que le groupe existe
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 * @cfg: pointeur sur une structure config_t obtenue
 *       precedemment par @controller_complete_from_file
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> le groupe n'existe pas
 */
static int controller_get_groupname(controller *ctrl, config_t *cfg){
    const char *str_tmp = NULL;
    size_t len_str =0;
    
    if(config_lookup_string(cfg, "SECURITY.groupname", &str_tmp)){
        len_str = strlen(str_tmp)+1;
        
        if(convert_groupname_to_gid(str_tmp)<0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] %s: le groupe %s n'existe pas sur le systeme.",
         config_error_file(cfg), str_tmp);
            return -1;
        }
        
        ctrl->groupname = calloc(len_str, sizeof(char));
        strncpy( ctrl->groupname, str_tmp, len_str-1 );
        
        SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: groupname -> %s",
         config_error_file(cfg), ctrl->groupname);
        return 0;
    }
    SLOGL_vprint(SLOGL_LVL_INFO,
        "[controller] %s: aucun groupe d'execution defini",
         config_error_file(cfg));
    return 0;
}


/**
 * CONTROLLER_SET_SECURITE
 * Permet de modifier l'utilisateur et le groupe effectif
 * du processus.
 * Si aucun utilisateur n'est défini, 
 * la fonction s'assure quand même que
 * le user actuel posséde la capacité @CAP_NET_ADMIN
 *
 * Valeur de retour
 * @0  -> SUCCESS
 * @-1 -> ERREUR 
 */
int controller_set_securite(controller *ctrl){
    uid_t executif_uid;
    gid_t executif_gid;
    
    if (set_proc_capabilities() !=0 ){
        return -1;
    }
    
    if( ctrl->groupname ){
        executif_gid = convert_groupname_to_gid(ctrl->groupname);
        
        if(setgid(executif_gid)!=0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Erreur lors de la définition du nouveau groupe effectif: %s", strerror(errno));
            return -1;
        }
        
        SLOGL_vprint(SLOGL_LVL_INFO,
"[controller] Le nouveau groupe effectif est %s.", ctrl->groupname);
    }
    
    if( ctrl->username ){
        executif_uid = convert_username_to_uid(ctrl->username);
        if(setuid(executif_uid)!=0){
            SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Erreur lors de la définition du nouvel utilisateur \
effectif.");
            return -1;
        }
        
        SLOGL_vprint(SLOGL_LVL_INFO,
"[controller] Le nouvel utilisateur effectif est %s.", ctrl->username);
    }
    
    
    
    set_proc_capabilities_after_seteuid();
    return 0;
}


/**
 * CONTROLLER_INIT_TAB_WORKERS
 * Initialise le tableau de pointeur de structure worker.
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
int controller_init_tab_workers(struct controller *ctrl){
    int i, queue_id;

      
    queue_id = ctrl->first_query_queue;
        
    for(i=0; i< ctrl->nb_workers*2 ; i++){
        
        if( controller_init_worker(ctrl, queue_id, i)!=0){
            return -1;
        }
        
        if (i+1==ctrl->nb_workers) queue_id = ctrl->first_response_queue;
        else queue_id++;
    }
    
    return 0;
}


/**
 * CONTROLLER_INIT_WORKER
 * Initialise un nouveau worker dans le tableau workerstab
 * de la structure @ctrl
 *
 * Parametres
 * @ctrl: pointeur sur une structure controller
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
static int controller_init_worker(controller *ctrl, int queue_id,
    int position)
{
    char *shm_name = NULL;
    int fd; 
    worker *wk = NULL;
        
    shm_name = calloc(25, sizeof(char));
    snprintf(shm_name, 25,"dns-rewriter_worker_%d", position);

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
        
    *(ctrl->workerstab + position) = wk;
    ctrl->running_worker += 1;
    wk->nfqueue_id = queue_id;
    wk->number = position;
    close(fd);
    return 0;
}


/**
 * CONTROLLER_GET_WORKER_BY_PID
 * Parcours la liste dew orkers à la recherche du worker
 * ayant le PID spécifié en paramètre
 */
static worker* controller_get_worker_bypid(controller *ctrl, pid_t pid){
    int i, max;
    worker *wk = NULL;
    max = ctrl->nb_workers * 2;
    
    for(i=0; i< max ; i++){
        wk =  (worker*)( *(ctrl->workerstab + i) );
        if((wk==NULL)||(wk->pid != pid)) continue;
        
        return wk;
    }
    
    return NULL;
}


/**
 * CONTROLLER_RESTART_WORKER
 * Redémarrage d'un worker identifié par son pid.
 * La fonction se charge d'arreter le worker, s'il est démarré.
 * 
 * Cette fonction est typiquement appelé en cas d'arret non
 * sollicite du worker ou en cas de besoin de reload de 
 * la configuration
 */
void controller_restart_worker(controller *ctrl, pid_t pid){
    int  qid, position;
    worker *wk = NULL;

    
    wk =  controller_get_worker_bypid(ctrl, pid);
    if(wk==NULL) return;
    
    if(ctrl->stopapp){
        SLOGL_vprint(SLOGL_LVL_ERROR,"Le controller a initié \
le processus d'arrêt. Relance du worker %d impossible", wk->number);
        return;
    }
    
    position = wk->number;
    SLOGL_vprint(SLOGL_LVL_INFO,"[controller] Redemarrage du \
worker %d", position);

    /**
     * Cas où le redemarrage a été initie par le controller
     * suite à la reception d'un signal demandant le reload
     * de la configuration. Les workers devront donc
     * etre redemarre
     */
    if (! (wk->operation_pending & RESTART_BY_CONTROLLER) )
    {
        wk->operation_pending |= RESTART_BY_CONTROLLER;
        controller_stop_worker(ctrl, position, SIGTERM);
        waitpid(wk->pid, NULL,0);
    }
    
    qid = wk->nfqueue_id;
    
    *(ctrl->workerstab + position) = NULL;
    shm_unlink(wk->shm_name);
    free(wk->shm_name);
    controller_init_worker(ctrl, qid, position);
    controller_fork_worker(ctrl, position);
}


/**
 * CONTROLLER_STOP_WORKER
 * Arret d'un worker par rapport à son matricule
 * (position dans la table des workers)
 * Le signal
 */
static void controller_stop_worker(controller *ctrl, int position, int signal)
{
        int ret;
        
        worker *wk = *(ctrl->workerstab + position);
        
        if (wk==NULL) {
            return;
        }
        
        if( (signal != SIGKILL) && (signal != SIGKILL) ){
            SLOGL_vprint(SLOGL_LVL_ERROR,"[controller] \
Erreur d'arrêt du worker, le signal %s n'est pas valide \
(SIGKILL ou SIGTERM uniquement). Envoie du signal SIGTERM.",
             sys_siglist[signal]);
             signal = SIGTERM;
        }
        
        /**
         * Si le fils n'est pas en fonctionnement,
         * on quitte la fonction
         */
        if(! (wk->operation_pending & RUNNING) ){
            return;
        }
        
        wk->operation_pending |= STOP_BY_CONTROLLER;
        ret = kill(wk->pid, signal);
         
        
        if(ret==0){
            SLOGL_vprint(SLOGL_LVL_INFO,"[controller] \
Envoie du signal %d au worker %d (pid=%d)",
signal, position, wk->pid);
        }
        else{
            SLOGL_vprint(SLOGL_LVL_ERROR,"[controller] \
Erreur lors de l'envoie du signal %d au worker %d (pid=%d): %s",
             signal, position, wk->pid, strerror(errno));
        }
}


/**
 * CONTROLLER_FORK_WORKER
 * Fork du processus controller, puis démarrage 
 * du nouveau worker.
 */
void controller_fork_worker(controller *ctrl, int position){
    worker *wk = NULL;
    pid_t pid;
    wk = *(ctrl->workerstab + position);
        
    pid = fork();
        
    switch (pid){
        case 0:
            wk->pid = getpid();
            wk->ppid = getppid();
                
            /*
             * A ce niveau là le fork a reussi (on est un worker)
             * On peut donc supprimer la structure CONTROLLER
             * (heritée du père).
             * On prend garde à ne pas se supprimer soit même
             * en se dereferencant de la struct controller
             */ 
            controller_free_all_worker_except(ctrl,wk);
            *(ctrl->workerstab + position) = NULL;
            controller_free(&ctrl,0);
            CONTROLLER = NULL;
                
            /*
             * On execute notre boucle de travail qui devra 
             * faire un exit(), pas de retour dans le main
             */
            worker_main(wk);
        case -1:
            SLOGL_vprint(SLOGL_LVL_ERROR,"[controller] \
Erreur lors du fork: %s", strerror(errno));
        default:
            SLOGL_vprint(SLOGL_LVL_INFO,"[controller] \
Creation d'un nouveau worker pid %d",pid);
            wk->pid = pid;
    }
}


/**
 * CONTROLLER_CONFIGURE_SIGNAUX
 * Configure la gestion des signaux sur le controller
 */
void controller_configure_signaux(void){    
    struct sigaction action;
    action.sa_sigaction = controller_gestionnaire_signal;
    sigemptyset( &(action.sa_mask));
    
    sigfillset( &(action.sa_mask));
    
    /**
     * On active les fonctions de, restart 
     * des appels systèmes lents en cas de récepeption
     * d'un signal, ainsi que les informations
     * étendus sur l'origine du signal
     */
    action.sa_flags =  SA_RESTART | SA_SIGINFO;
    
    /**
     * On intercepte uniquement les signaux
     * @SIGINT et @SIGTERM pour l'arret
     * @SIGCHLD pour la gestion des workers
     * TODO: @USR1 pour le reload de la conf
     */
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGCHLD, &action, NULL);
}



/**
 * CONTROLLER_GESTIONNAIRE_SIGNAL
 * Handler pour les différents signaux
 */
void controller_gestionnaire_signal(int numero, 
            siginfo_t *info, void *data)
{
    int pid;

    switch(numero){
        case SIGCHLD:
            /**
             * Linux n'est pas un système temps réel, 
             * de ce fait les signaux identiques ne sont pas empilables
             * ex:la réception de 20 signaux identiques entraine
             *    le traitement du premier via le handler definit,
             *    le second est conservés empile, mais les 18 autres
             *    seront perdus.
             * Afin de gérer l'arrêt de plusieurs processus fils 
             * (envoie du signal SIGCHLD par le noyau), le noyau Linux
             * peut être emmené à n'envoyer qu'un seul signal.
             * 
             * S'est alors au processus pere de verifier lequel de
             * ses fils s'est arrêté.
             *
             * -1       -> parcours l'ensemble des processus fils
             * WHNOHANG -> ne pas rester bloquer si le fils
             *             n'a pas fini  
             */
            while ( (pid=waitpid((pid_t)(-1), 0, WNOHANG)) > 0){
                controller_manager_endofworker(CONTROLLER, pid);
            }
            
            break;
        case SIGINT:
            controller_kill_worker(CONTROLLER);
            break;
        case SIGTERM:
            controller_kill_worker(CONTROLLER);
            break;
        default:
            break;
    }
}


/**
 * CONTROLLER_MANAGE_ENDOFWORKER
 * Gestion de l'arret d'un worker.
 * On verifie notament si le noeud s'est arrête à l'initiative
 * du controller ou suite à une erreur.
 * On le redemarre au besoin. 
 */
void controller_manager_endofworker(controller *ctrl, int pid){
    worker *wk = NULL;
    
    wk = controller_get_worker_bypid(CONTROLLER,pid);
    
    if(wk==NULL) return;        
    CONTROLLER->running_worker--;
            
    if( (!(wk->operation_pending & STOP_BY_CONTROLLER)) &&
        (!(wk->operation_pending & RESTART_BY_CONTROLLER)) )
    {
        SLOGL_vprint(SLOGL_LVL_ERROR,"[controller] \
Terminaison non sollicite du worker %d avec status=%d",
        wk->number, wk->status);
                
        /**
         * Si le worker quitte avec une erreur critique,
         * on considere que son redemarrage risque
         * d'entrainer une boucle d'erreur, on ne le traite donc pas.
         * A noter qu'on aurait aussi pu choisir de se baser
         * sur la valeur de retour du worker plutôt que sur
         * de la mémoire partagée.
         */
        if( wk->status != CRITICAL_ERROR){
            wk->operation_pending |= RESTART_BY_CONTROLLER;
        }
        
        else {
            SLOGL_vprint(SLOGL_LVL_FATAL,"[controller] \
Le worker %d s'est arrete avec une erreur critique. \
Redemarrage non effectue",
        wk->number);
        }
        
        
        /**
         * COMMENTAIRE POUR SUIVI:  
         * Initialement, le worker en defaut etait relance
         * ici, c'est à dire dans le handler du signal.
         * Bien que l'appel systeme fork soit async safe,
         * on rencontrait des problèmes dans la gestion
         * des signaux sur le nouveau worker; les handlers
         * n'etait pas applique et on se coltinner ceux
         * par defaut.
         * Le redemarrage a donc maintenant lieu dans 
         * la boucle main en sortie de handler
         */
        
        //controller_restart_worker(CONTROLLER, pid);
    }
}


/**
 * CONTROLLER_KILL_WORKER
 * Envoie une demande d'arrêt à tous les workers.
 * S'il s'agit de la première demande, on envoie le signal
 * @SIGTERM afin de permettre au worker de finir une éventuelle
 * tache en cours.
 * Le second appel de la fonction enverra le signal @SIGKILL
 * pour forcer l'arrêt du worker.
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
void controller_kill_worker(controller *ctrl){
    int max, i;
    int signal;
    
    if (ctrl==NULL) return;    
    max = ctrl->nb_workers *2;
    
    if(!ctrl->stopapp){
        signal= SIGTERM;
    }
    else{
        signal = SIGKILL;
    }
    
    for(i=0; i<max; i++){
        controller_stop_worker(ctrl, i, signal);
    }
    
    /**
     * On indique qu'on a deja effectue une tentative d'arret
     * Si on reitere la demande d'arret par la suite, les 
     * 2 premiers if en debut de fonction permettront
     * de forcer l'arrêt du worker par le signal @SIGKILL
     * au lieu de @SIGTERM
     */
    ctrl->stopapp = 1;
}
