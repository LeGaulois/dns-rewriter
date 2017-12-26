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




static char hex [] = { '0', '1', '2', '3', '4', '5', '6', '7',
                        '8', '9' ,'A', 'B', 'C', 'D', 'E', 'F' };
 
/**
 * CONVERT_INT_TO_HEX
 * Convertit un entier en hexadecimal
 */
int convert_int_to_hex(unsigned int num, char* buff)
{
    int len=0,k=0;
    do
    {
        buff[len] = hex[num&0xF];
        len++;
        num>>=4;
    }while(num!=0);
    
    for(;k<len/2;k++)
    {
        buff[k]         ^= buff[len-k-1];
        buff[len-k-1]   ^= buff[k];
        buff[k]         ^= buff[len-k-1];
    }

    buff[len]='\0';
    return len;
}


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
    
    mask = mask<<(31-bitstart);
    
    while(count<nbread){
        if (base&mask) return_int += pow(2, count);
        mask = mask >> 1;
        count++;
    }

    //fprintf(stderr,"\t return_int: %d\n", return_int);
    return return_int;
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
