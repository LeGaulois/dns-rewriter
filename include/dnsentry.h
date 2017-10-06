#ifndef DNS_REWRITE_ENTRY_H
#define DNS_REWRITE_ENTRY_H

/*
* Structure DNS entry, correspond
* à un enregistrement de récriture DNS
* lu à partir d'un fichier
* 
* - initialentry: valeur du champ question DNS
* - labelized_entry: valeur du champ reecris
* - type d'enregistrement DNS (A, MX,...)
*  On chosiit de reecrire quelque soit l'enregistrement'
*
*/

typedef struct dns_rewrite_entry{
    char    *initialentry;
    char    *labelized_entry;
};

#endif
