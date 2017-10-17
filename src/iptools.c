#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

/** 
 * convert_ipadress_to_binary - convertit une adresse IP
 * sous forme de char en mot de 4 octets
 * @ipaddress: adresse IPv4
 * @binaryaddr: pointeur sur un mot de 4 octets
 *
 * Valeur de retour:
 * @0: OK
 * @-1: en cas d'erreur
 */
int convert_ipadress_to_binary(char *ipaddress, uint32_t *binaryaddr)
{
    size_t octet_size;
    int i=0, j=0;
    long bigoctet;
    uint32_t octet, bintemp=0;
    char *actuel=NULL, *tmp=NULL;
    
    if ((ipaddress==NULL)||(binaryaddr==NULL)) return -1;
    actuel=ipaddress;
    
    for(i=0; i<4; i++){
        j=i;
        octet_size = strcspn(actuel, ".");
        
        if ( octet_size>3 ) goto error;
    
        /*
         * On recupere l'octet sous forme de texte que
         * l'on convertit en entier
         * On verifie ensuite que sa valeur est comprise entre 0 et 255
         */    
        tmp = strndup(actuel, octet_size);
        actuel = actuel+ octet_size+1;
        
        errno       = 0;
        bigoctet    = strtol(tmp, NULL, 10);
        
        if ((errno == ERANGE && 
            (bigoctet == LONG_MAX || bigoctet == LONG_MIN))
            || (errno != 0 && bigoctet == 0)) 
        {
            fprintf(stderr, "Erreur de convertion str->int: %s",
                strerror(errno));
            goto error;
        }
        
        if ((bigoctet>255)||(bigoctet<0)||((bigoctet==0)&&(i==0))) goto error;
        free(tmp);
        
        octet = (uint32_t)(bigoctet);
        
        
        /* 
         *A ce niveau là on a octet code sur 32 bits
         * mais avec une valeur max de 255 (donc codable sur 8 bits)
         * On veut le concatener avec notre word_ipaddress sur 32 bits
         * On decale donc succ
         */
        while (j<3){
            octet = octet<<8;
            j++;
        } 
        
        bintemp = bintemp | octet;  
    }
    
    *binaryaddr = bintemp;
    
    return 0;
    
    error:
        free(tmp);
        fprintf(stderr,"Invalide IP adress");
        return -1; 
}   



/** 
 * convert_netmask_to_binary
 * Convertit un netmask sous forme CIDR
 * en netmask binaire sous 32 bits
 * @netmaskcidr: netmask sous forme CIDR (ex: /24)
 * @binarynetmask: pointeur sur un mot de 4 octets
 *
 * Valeur de retour:
 * @0: OK
 * @-1: en cas d'erreur
 */
int convert_netmask_to_binary(int netmaskcidr, uint32_t *binarynetmask)
{

    if ((netmaskcidr<0)||(netmaskcidr>32)||(binarynetmask==NULL)){
        return -1;
    }
     
    *binarynetmask = 0;
    *binarynetmask =~ *binarynetmask;
    *binarynetmask = *binarynetmask<<(32-netmaskcidr);
    
     return 0;
}  


/** 
 * get_network_address
 * Obtenir l'adresse réseau à partir d'une adresses IP
 * et d'un netmask
 * @hostaddr: adresse IPv4 d'un hôte en binaire
 * @mask: netmask en binaire
 *
 * Valeur de retour:
 * @NULL: en cas d'erreur d'allocation
 * @POINTEUR: sinon
 */
uint32_t* get_network_address(uint32_t hostaddr, uint32_t mask){
    uint32_t *network_address = NULL;
    
    network_address = calloc(1, sizeof(uint32_t));
    
    if (network_address==NULL) return NULL;
    *network_address = hostaddr & mask;
    
    return network_address; 
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
    
    mask = 1<<31;
    
    for (i=0;i<32;i++){
        if (binary_number&mask){
            str_number[i]='1';
        }
        else{
            str_number[i]='0';
        }
        mask = mask >>1;
    }
    
    return str_number;  
}


/**
 * get_networkaddress_and_mask_from_char
 * Récupere à partir d'un string de type ipaddress/netmask
 * l'adresse IP réseau associé, ainsi que le cidr au format int
 * @ipaddrandmask: adresse ip et masque au format CIDR
 *                 (ex: 10.0.1.2/24)
 * @netaddr: double pointeur sur l'adresse reseau au format binaire
 * @cidr: double pointeur sur un entier permettant de récupérer
 *        le masque cidr sous fomr d'entier
 *
 * Valeurs de retour
 * @0: en cas de SUCCESS
 * @-1: en cas d'erreur
 */
int get_networkaddress_and_mask_from_char(
    char *ipaddrandmask, uint32_t **netaddr, int **cidr)
{
    char *tmp = NULL, *cache = NULL;
    uint32_t *mask = NULL, *hostaddr = NULL;
    size_t str_len = 0;
    
    *netaddr=NULL;
    *cidr=NULL;
    
    mask = calloc(1, sizeof(uint32_t));
    if ( mask==NULL ) return -1;
    
    hostaddr = calloc(1, sizeof(uint32_t));
    if ( hostaddr==NULL ){
        free(mask);
        return -1;
    } 
    
    cache = ipaddrandmask;
    str_len = strcspn(cache, "/");
    tmp = strndup(cache, str_len);
    
    if (convert_ipadress_to_binary(tmp, hostaddr)!=0){
        free(tmp);
        goto error;
    };
    

    free(tmp);
    cache = cache+str_len+1;
    
    *cidr = calloc(1, sizeof(int));
    if (cidr==NULL) goto error;
    
    errno = 0;
    **cidr = strtol(cache, NULL, 10);

    if ((errno == ERANGE && 
        (**cidr == LONG_MAX || **cidr == LONG_MIN))
        || (errno != 0 && **cidr == 0)) 
    {
        fprintf(stderr, "Erreur de convertion str->int: %s",
        strerror(errno));
        goto error;
    }

    if (convert_netmask_to_binary(**cidr, mask)!=0) goto error;
    *netaddr = get_network_address(*hostaddr, *mask);
    
    
    free(hostaddr);
    free(mask);
    return 0;
    
    error:
        free(cidr);
        free(hostaddr);
        free(mask);
        return -1;
}
