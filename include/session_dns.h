#ifndef SESSION_DNS_H_INCLUDED
#define SESSION_DNS_H_INCLUDED


/*
* SESSION_DNS
* Structure permettant d'enregistrer une 'session'
* DNS en cours de traitement (pas encore renvoyee au client).
*
* Cette structure permet de matcher la reponse reçue du resolveur
* avec la requete initiale du client.
*
* Le but est ensuite de pouvoir reecrire la reponse pour la faire
* correspondre avec la(les) question(s) initiales du client
* avant reecriture.
*/

typedef struct session_dns session_dns;

struct session_dns {
    unsigned int        rewrite_done:1;
    
    char                ip_client[16];
    unsigned int        port_client:16;
    
    unsigned int        transaction_id:16;         
    unsigned int        nb_questions:16;
    dns_rewrite_entry   *questions; 
};

#endif
