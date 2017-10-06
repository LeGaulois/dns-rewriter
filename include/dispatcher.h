#ifndef GENERAL_H
#define GENERAL_H

typedef struct dispatcher dispatcher;
    
/*
* Constantes pour parametre default_action
*/
#define PASS    0
#define BLOCK   1
#define SILENT  2

/*
* STRUCTURE DISPATCHER
* Centralise toutes les variables permettant la gestion
* et la configuration du programme
*
* [General]
*   - parameters_file: chemin du fichier contenant toutes
*     parametres permettant de completer cette structure
*     Cet element sera utilisé notament pour rescanner
*     le fichier en cas de reload du programme
*
*   - range_file: chemin du fichier contenant la correspondance
*     NOM_POP;range_IP  
*     ex: pop1;192.168.1.0/24,192.168.3.0/24
*         pop2;192.168.2.0/24
*
*   - dnsentry_file: chemin du fichier contenant la liste
*     de reecriture.
*     ex: A example.com   $name$.example.com
*         A content.com   www.$name$.content.com
*
*   - default_pop: nom du pop par defaut si aucune correspondance
*     trouvée. Si NULL, aucune réecriture ne sera faites et
*     l'action par default sera appliquée
*
*   - default_action: action par defaut si aucune correspondance
*     n'est trouve dans dnsentry_file
*     Peux prendre les valeurs suivantes:
*       $ PASS: aucune reecriture n'est effectué
*       $ BLOCK: le paquet est bloque via l'envoi d'un message
*         adequat sur netfilter
*       $ SILENT: le message n'est pas forwarde, mais aucun
*         message d'erreur ne sera envoye par iptables
*
*
* [Logs]
*   - log_general_file: log general dcrivant les actions effectues
*     ou les problèmes en fonction du parametre debug_level
*   
*   - debug_level: niveau de declenchement des logs. Peut prendre 
*     les valeurs parmis DEBUG,INFO,NOTICE,WARNING,ERROR,FATAL
*
*   - log_rewrite_file: chemin du fichier de logs contenant
*     l'historique des reecritures DNS
*
* [REMOTE]
*   A voir si on conserve, pour l'instant on se concentre sur 
*   de la redirection local
*
* [WORKER]
*   Correspond aux forks du programmes qui seront lancés pour traiter
*   les requêtes des clients.
*   - nb_workers: nombre de worker qui seront instanciés
*   - workers: pointeur sur une liste de struct avec toutes 
*       les informations propre au worker
*   TODO: voir si a passer en GLOBAL
*
* [SEARCH DATA]
*   Ensemble des éléments qui seront à utiliser pour la recherche
*   d'informations
*   - fd_dns_entry: descripteur de fichier sur la zone memoire partagee
*       TODO: voir mecanisme daccess concurent pour la zonne memoire
*       essentiellement en cas de reecriture lors du reload du service.
*       Voir mutex R/W ou autre
*   - dnsentries: pointeur sur notre hashtable, la taille de la table
*       dépendera du nombre d'entree DNS a charger.
*   - nb_dnsentries: nombre d'entres DNS pour lesquelles on gere
*        la reecriture. On pourra l'obtenir lors du parsing du fichier
*        defini par "dnsentry_file"
*   - size_hashtable: taille de la table de hashage 
*        TODO: verifier taille ideal, de memoire size=2 * NBentrees
*   
*   - fd_tree_binary:  descripteur de fichier sur la zone memoire partagee
*       TODO: voir mecanisme daccess concurent pour la zonne memoire
*       essentiellement en cas de reecriture lors du reload du service.
*       Voir mutex R/W ou autre
*   -  root_tree: racine de l'arbre binaire. On y indiquera l'action par defaut
*       TODO: definir la structure ntree_binary par rapport au cours
*           de ROUT
*   - n_stride: correspond au nombre de branches par noeud de l'arbre.
*       Permet d'acceler la recherche. Partir sur n=2(bits), soit
*       4 branches par noeud    
*
*/

struct dispatcher {
    /*GENERAL*/
    char                *parameters_file;
    char                *range_file;
    char                *dnsentry_file;
    char                *default_pop;
    unsigned int        default_action:2; 
    
    /*LOGS*/
    char                *log_general_file;
    unsigned int        debug_level:3;
    char                *log_rewrite_file; 
    
    /*REMOTE*/
    char                *dns_remote_address;
    int                 dns_remote_port;
    unsigned int        dns_remote_proto:2;
   
   
    /*WORKER*/ 
    int                 nb_workers;
    worker              *workers;
  
    /*SEARCH DATA*/
    int                 fd_dns_entry;  
    list                *dnsentries;
    int                 nb_dnsentries;
    int                 size_hashtable;
    
    int                 fd_tree_binary;
    ntree_binary        root_tree;  
    int                 n_stride;
};


#endif
