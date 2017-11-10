#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dns_translation.h"



/**
 * DNS_TRANSLATION_INIT
 * Initialisation d'une structure dns_translation
 * 
 * Valeurs de retour
 * @NULL: Erreur d'allocation
 * @PTR: OK
 */
dns_t* dns_translation_init(){
    dns_t *dns = NULL;
    
    dns = calloc(1, sizeof(dns_t));
    if(dns==NULL) return dns;
    
    dns->query      = NULL;
    dns->rewrited   = NULL;
    return dns;
}


/**
 * DNS_TRANSLATION_FREE
 * Libére la mémoire alloué à la structure
 * dns_translation
 * @dns: addresse sur du pointeur pointant
 *       sur une structure de type dns_translation
 */
int dns_translation_free(void **dns) 
{
    dns_t *cache = NULL;
    cache = (dns_t *)(*dns);
    
    if( *dns == NULL) return 0;
    if (cache->query != NULL) free(cache->query);
    if (cache->rewrited != NULL) free(cache->rewrited);
    free(*dns);
    return 1;
}


/**
 * DNS_TRANSLATION_COMPARE_STRUCT
 * Compare 2 pointeur sur un structure 
 * de type dns_translation.
 *
 * Valeurs de retour
 * @0: SUCCESS
 * @-1: dns1 different de dns2
 * @-2: un des pointeurs est NULL
 */
int dns_translation_compare_struct(void *dns1, void *dns2) 
{
    dns_t *d1, *d2;
    
    if ((dns1==NULL)||(dns2==NULL)) return -2;
    
    d1 = (dns_t*)(dns1);
    d2 = (dns_t*)(dns2);
    
    if ((strcmp(d1->query, d2->query)!=0)&&
        (strcmp(d1->rewrited, d2->rewrited)!=0))
    {
            return -1;
    }
    return 0;
}

/**
 * DNS_TRANSLATION_COMPARE_QUERY
 * Compare 2 pointeur sur un structure 
 * de type dns_translation.
 *
 * Valeurs de retour
 * @0: SUCCESS
 * @-1: dns1 different de dns2
 * @-2: un des pointeurs est NULL
 */
int dns_translation_compare_query(void *strquery, void *dns1) 
{
    dns_t *d1;
    char *str1 = NULL;
    
    if ((dns1==NULL)||(strquery==NULL)) return -2;
    
    d1 = (dns_t*)(dns1);
    str1 = (char *)(strquery);
    
    if ( strcmp(str1, d1->query)!=0)
    {
            return -1;
    }
    return 0;
}


/**
 * HASHTABLE_COMPLETE_FROM_FILE
 * Remplie une table de hashage à partir d'un fichier
 * test.
 * Le fichier peut contenir des commentaires: lignes commencant
 * par un "#"
 * Sinon chaque ligne d'enregistrement comporte
 * initial_query [\t ]{1,n} rewrited_query
 *
 * Paramètres
 * @ht: pointeur sur la table de hashage
 * @file: fichier à analyser
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERREUR
 */
int hashtable_complete_from_file(hashtable *ht, char *file){
    int fd;   
    
    fd = open(file, O_RDONLY);
    
    if(fd<0){
        fprintf(stderr, "Erreur lors de l'ouverture: \
             %s. \n", strerror(errno));
        return -1;
    }
    
    read_dnspopfile(fd, ht);
    
    if(close(fd)<0){
        fprintf(stderr, "Erreur lors de la fermeture: %s. \n", strerror(errno));
        return -1;
    }
    return 0;
}


/**
 * HASHTABLE_ADD_ENTRY_FROM_LINE
 * 
 * Paramètres
 * @ht: pointeur sur la table de hashage
 * @line: ligne du fichier
 *
 * Valeur de retour
 *  0 -> SUCCESS
 * -1 -> ERROR
 */
int hashtable_add_entry_from_line(hashtable *ht, char line[]){
    size_t size_str = 0;
    dns_t *dns = NULL;
    
    dns = dns_translation_init();
    if(dns==NULL) return -1;
    
    size_str = strcspn(line,"\t ");
    dns->query = strndup(line, size_str);
    
    line = line + size_str;
    size_str = strspn(line, "\t ");
    line = line + size_str;
    dns->rewrited = strndup(line, strlen(line));

    
    if((dns->query==NULL)||(dns->rewrited==NULL)) return -1;
    hashtable_add_element(ht, dns->query, (void *)(dns));
    return 0;
}


/**
 * READ_DNSPOPFILE
 * 
 */
void read_dnspopfile(int fd, hashtable *ht){
    char buffer[1024];
    int i=0, nb=0;
    static char cache[1024];
    static int j=0;
    
    do{
        nb = read(fd,(void*)(buffer),1023);
            
        if(nb>0){
            if(nb<1023){
                buffer[nb]='\0';
            }
                       
            for(i=0; i<nb ;i++){
                cache[j] = buffer[i];
                
                if(cache[j] == '\n'){
                    cache[j]='\0';
                    j=0;
                    
                    //Commentaire ou ligne vide
                    if ((cache[0]=='#')||(cache[0]=='\0')) continue;
                    hashtable_add_entry_from_line(ht,cache);
                    continue;
                }
                j++;  
            }
        }
        else if(nb==0){
            break;
        }
        else{
            fprintf(stderr,"\nErreur: %s.\n", strerror(errno));
            break;
        }
        
    }while(1);
}
