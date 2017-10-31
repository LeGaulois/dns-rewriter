#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include "ntree_binary.h"
#include "iptools.h"
#include "tools.h"
#include <arpa/inet.h>


/** 
 * get_n_bits_from_uint32t
 * renvoie n bits d'un entier de 32 bits
 * @base: nombre sur 32 bits 
 * @bitstart: position du bit du depart
 * @nbread: nombre de bits à lire
 */

uint8_t get_n_bits_from_uint32t(uint32_t base, int bitstart, int nbread){
    uint8_t return_int=0;
    uint32_t mask=1;
    int count = 0;
    
    mask = mask<<bitstart;
    
    while(count<nbread){
        if (base&mask) return_int += pow(2, nbread-count-1);
        mask = mask << 1;
        count++;
    }

    return return_int;
}


int root_add_data_from_range_line(ntree_root *root, char line[]){
    size_t size_str = 0;
    char *pop = NULL, *ipaddress = NULL;
    uint32_t *netaddr=NULL;
    int ret, *mask=NULL;
    
    size_str = strcspn(line,"\t ");
    pop = strndup(line, size_str);
    
    line = line + size_str;
    size_str = strspn(line, "\t ");
    line = line + size_str;
    ipaddress = strndup(line, strlen(line));
    
    ret = get_networkaddress_and_mask_from_char(ipaddress, &netaddr, &mask);
    
    if ( ret!=0 ){
        free(pop);
        free(ipaddress);
        return -1;
    }
    
    ret = ntree_root_add_data(root, uint32_t_invert(*netaddr), *mask, (void *)pop, strlen(pop)+1);
    
    if (ret==-1) free(pop);
    free(netaddr);
    netaddr = NULL;
    free(mask);
    mask = NULL;

    free(ipaddress);
    return ret;
}


/**
 * uint32_t_to_char
 * Convertie un entier binaire sur 32 bits en string affichable
 * 
 * @binary_number: nombre binaire sur 32 bits (ex: adresse IPv4)
 *
 * Valeurs de retour:
 * @NULL en cas d'echec
 * @CHARPOINTEUR sinon
 */
char* uint32_t_to_char(const uint32_t binary_number){
    char *str_number = NULL;
    uint32_t mask;
    int i=0;
    
    str_number = calloc(33, sizeof(char));
    
    if ( str_number==NULL ) return NULL;

    mask = 1;
       
    for (i=0;i<32;i++){
        if (binary_number&mask){
            str_number[i]='1';
        }
        else{
            str_number[i]='0';
        }
        
        mask = mask <<1;
    }
    
    return str_number;  
}


/**
 * UINT32_T_INVERT
 * Inverse la position de l'ensemble des bits
 * bits 0 -> bits 31, ....
 *
 */
uint32_t uint32_t_invert(uint32_t addr){
    uint32_t ret = 0, tmp;
    int position = 31;
    
    while (addr){
        tmp = 1<<position;
        
        if (addr & 1) ret = ret | tmp;
        
        addr >>=1;
        position--;
    }
    
    return ret;
}


void lecture_fd_rangefile(int fd, ntree_root *root){
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
                    
                    //Comment ou ligne vide
                    if ((cache[0]=='#')||(cache[0]=='\0')) continue;
                    root_add_data_from_range_line(root,cache);
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
