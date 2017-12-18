#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "dnsentry.h"


/*
* convert_dnsentryfile_to_hashtable:
* Cette fonction permet créer une table de hashage
* a partir d'un fichier contenant les entrees DNS
* et leur correspondance de reecriture
*
*/
int convert_dnsentryfile_to_hashtable(
    const char *dnsentryfilepath,
    int *hashtable)
{
    int fd;
    
    fd = open(argv[1], O_RDONLY);
    
    if(fd<0){
        fprintf(stderr, "Erreur lors de l'ouverture de %s: \
             %s. \n", dnsentryfilepath, strerror(errno));
        return -1;
    }
    
    
    
}

/*
* estimate_hashtablefile_from_fd_ofdnsentryfile
* Cette fonction permet d'estimer la taille
* finale de la projection en memoire de la hashtable.
* Paramètres à prendre en compte:
* - nombre de lignes (ex 100), on en deduit: 
*       + la taille de la hashtable
*         (NB lignes *2) et la taille occupee par 
*         cette ensemble de liste
*         ex: 200 struct list
*       + le nombre de structure dnsentries (100)  
* - la taille du fichier: permet d'évaluer la taille
*   des string representant les enregistrement DNS
*   Il faudra penser à rajouter la place pour 2 '\0'
*    par ligne
*/

int estimate_hashtablefile_from_fd_ofdnsentryfile(int fd){
    
}


/*
* FIXME changer nom fonction + description + valeur retour
*/

void lecture_fd(int fd){
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
                    cache[j+1]='\0';
                    fprintf(stdout, "%s",cache);
                    
                    /*
                    * TODO
                    * A ce niveau la on appelle 
                    * notre fonction de parsing
                    */
                    j=0;
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

