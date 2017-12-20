#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "ntree_binary.h"
#include "iptools.h"
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "tools.h"



/*
 * Variables de tests
 */
#define nbcontrol 6

struct check {
    char ipaddress[50];
    char popdesired[50];
};

static struct check control[]= {
    {"192.168.3.67","POP63"},
    {"192.168.9.12","POP666"},
    {"89.67.12.12","POP102"},
    {"127.0.0.1","TEST"},
    {"192.168.10.0","POP70"},
    {"1.2.3.4","DEFAULT"}
};


/*
 * Fonctions de gestion des DATA des noeuds
 */
int cmp_data(void *data1, void *data2){
    return strcmp((char *)data1, (char *)data2);
}


int free_datanode(void *data){
    free(data);
    return 1;
}


int main(){

    char *str = NULL;
    int number=1, i;
    int fd;
    ntree_root *root=NULL;
    
    root = ntree_root_init(2, &free_datanode);
    uint32_t *test= malloc(1*sizeof(uint32_t));    
    
    
    fd = open("range_to_zone.cfg", O_RDONLY);
    
    /*
     * Peuplement de l'arbre à partir d'un fichier
     */
    if(fd<0){
        fprintf(stderr, "Erreur lors de l'ouverture: \
             %s. \n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    lecture_fd_rangefile(fd, root);
    
    if(close(fd)<0){
        fprintf(stderr, "Erreur lors de la fermeture: %s. \n", strerror(errno));
        return EXIT_FAILURE;
    }
    
    
    /*
     * Test de performance
     * Recherche 1 millions de fois une valeur
     * dans l'arbre
     */
     
    number=1000000;
    while(number>0){
        convert_ipadress_to_binary("192.168.9.2", test );
        ntree_root_lookup(root,*test);
        number--;
    }

    /*
     * Test sur des valeurs précises
     */
    for (i=0;i<nbcontrol;i++){
        convert_ipadress_to_binary(control[i].ipaddress, test );
        fprintf(stderr,"%s\n",uint32_t_to_char(*test));
        str = (char *)(ntree_root_lookup(root,*test)); 
        
        if((str==NULL)||(strcmp(str, control[i].popdesired)!=0)){
            fprintf(stderr,"[Test %d failed] recv: %s, desired: %s\n",i, str, control[i].popdesired);
        }
    }

    ntree_root_free(&root);
    free(test);
    return EXIT_SUCCESS;
}
