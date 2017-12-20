#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <sys/types.h> 
#include <sys/types.h>
#include <grp.h>
#include "logger.h"


extern SLOGL_level programLevel;


/**
 * CONVERT_USERNAME_TO_UID
 * Permet d'obtenir l'uid d'un utilisateur
 * à partir de son username
 */
uid_t convert_username_to_uid(const char *username){
    
    struct passwd *p = NULL;
    p = getpwnam(username);
    endpwent();
    
    if(p){
        return p->pw_uid;
    } 
    return -1;
}


/**
 * CONVERT_GROUPNAME_TO_UID
 * Permet d'obtenir le gid d'un groupe
 * à partir du groupname
 */
gid_t convert_groupname_to_gid(const char *groupname){
    
    struct group *g = NULL;
    g = getgrnam(groupname);
    endpwent();
    
    if(g){
        return g->gr_gid;
    } 
    return -1;
}


/**
 * SET_PROC_CAPABILITIES_AFTER_SETEUID
 * Cette fonction permet de re-appliquer les capacités
 * du processus après avoir fais le changement
 * d'utilisateur effectif du processus.
 */
int set_proc_capabilities_after_seteuid(void){
    cap_t caps;
    cap_value_t cap_values[] = {CAP_NET_ADMIN};
    
    caps = cap_get_proc();
    cap_set_flag(caps, CAP_EFFECTIVE, 1, cap_values, CAP_SET);
    cap_set_proc(caps);
    cap_free(caps);
    return 0;
}


/**
 * SET_PROC_CAPABILITIES
 * Ajoute la capacité @CAP_NET_ADMIN au processus.
 * Cette capacité est requise par netfilter pour
 * l'interception de paquets
 *
 * Valeurs de retour
 * 0  -> SUCCESS
 * -1 -> FAIL
 */
int set_proc_capabilities(void){
    cap_t caps;
    cap_value_t cap_list[1];

    if (!CAP_IS_SUPPORTED(CAP_SETFCAP)){
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Les delegations de privileges ne sont pas supportées \
sur cette version de noyau.");
        return -1;
    }

    caps = cap_get_proc();
    if (caps == NULL){
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Impossible de récupérer les privileges actuels du processus");
        return -1;
    }

    /**
     * Privileges pour les queues de netfilter
     */
    cap_list[0] = CAP_NET_ADMIN;

    if (cap_set_flag(caps, CAP_PERMITTED, 2, cap_list, CAP_SET) == -1){
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Erreur de création de la liste des privileges.");
    return -1;
    }

    if (cap_set_proc(caps) == -1){
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Erreur d'application des privileges au processus");
        return -1;
    }

    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);
    if (cap_free(caps) == -1){
        SLOGL_vprint(SLOGL_LVL_ERROR,
"[controller] Erreur de libéation de la liste des privileges.");
        return -1;
    }
    
    
    
    return 0;
}

