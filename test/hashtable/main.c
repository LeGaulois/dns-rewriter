#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "hash.h"
#include "dns_translation.h"


struct check {
    char initial_query[50];
    char query_rewrited[50];
};

#define nbcontrol 6

static struct check control[]= {
    {"content.com","$name$.cdn.com"},
    {"coucou.com","$name$.coucou.com"},
    {"toto.com","$name$.toto.com"},
    {"tata.com","$name$.tata.com"},
    {"titi.com","$name$.titi.com"},
    {"eatmycouilles.fr", ""}
};


int main(){
    
    hashtable *ht = NULL;
    int ret=0;
    
    /*
     * FIXME: Ajouter une etape d'évaluation de la taille voulue
     * par rapport au fichier (nombre de lignes)
     */ 
     
    ret = hashtable_init(&ht, 128, &dns_translation_free,
     &dns_translation_compare_query);
    
    if ( ret !=0 ){
        fprintf(stderr,"Erreur d'allocation de la hashtable\n'");
        return EXIT_FAILURE;
    }
    
    ret = hashtable_complete_from_file(ht, "dnsentry.cfg");
    
    if ( ret !=0){
        fprintf(stderr,"Erreur d'import du fichier\n");
        hashtable_free(&ht);
        return EXIT_FAILURE;
    }
    
    /*
     * Verification par rapport au jeu de test defini plus haut
     */
    dns_t *d = NULL;
    int i =0;
    
    for (i=0;i<nbcontrol;i++){
        d = (dns_t *)(hashtable_get_element(ht,
            control[i].initial_query));
    
        if (d!=NULL){
            if (strcmp(d->rewrited, control[i].query_rewrited)==0){
                fprintf(stdout,"Test[%d] ==> OK\n", i);
            }
            else{
                fprintf(stdout,"Test[%d] ======> NOK\n", i);
                fprintf(stderr,"\t get: %s \t desired:%s\n", 
                    d->rewrited,control[i].query_rewrited);
            }
        }
        
        else if (!strcmp(control[i].query_rewrited,"")){
            fprintf(stdout,"Test[%d] ==> OK\n", i);
        }
        else {
            fprintf(stdout,"Test[%d] ======> NOK\n", i);
        }
    }
    
    
    hashtable_free(&ht);
    return EXIT_SUCCESS;
}
