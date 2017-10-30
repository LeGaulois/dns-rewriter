#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <endian.h>
#include "ntree_binary.h"
#include "iptools.h"
#include "tools.h"


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
    int i=0;
    unsigned int byte[4]={0};
    char *actuel=NULL, *tmp=NULL;
    
    if ((ipaddress==NULL)||(binaryaddr==NULL)) return -1;
    actuel=ipaddress;
    
    for(i=0; i<4; i++){
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
        byte[i]  = (unsigned int)(strtol(tmp, NULL, 10));
        
        if ((errno == ERANGE && 
            (byte[i] == LONG_MAX || byte[i] == LONG_MIN))
            || (errno != 0 && byte[i] == 0)) 
        {
            fprintf(stderr, "Erreur de convertion str->int: %s",
                strerror(errno));
            goto error;
        }
        
        if ((byte[i]>255)||(byte[i]<0)||
            ((byte[i]==0)&&(i==0))) goto error;
            
        free(tmp); 
    }
    
    *binaryaddr = (byte[0]<<24)+(byte[1]<<16)+ (byte[2]<<8)+(byte[3]);    
    return 0;
    
    error:
        free(tmp);
        fprintf(stderr,"Invalid IP address");
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
    
    if(netmaskcidr>0){
        *binarynetmask =~ *binarynetmask;
        *binarynetmask = *binarynetmask<<(32-netmaskcidr);
    }
    
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
    char *tmp = NULL;
    uint32_t *mask = NULL, *hostaddr = NULL;
    size_t size_ipstr = 0, size_maskstr;
    
    *netaddr    = NULL;
    *cidr       = NULL;
    
    mask = calloc(1, sizeof(uint32_t));
    if ( mask==NULL ) return -1;
    
    hostaddr = calloc(1, sizeof(uint32_t));
    if ( hostaddr==NULL ){
        free(mask);
        return -1;
    } 
    
    /**
     * On controle la taille de nos différents éléments
     * @IP: (3*int)*4+(3*.)*3 = 15
     * @mask: 2*int = 2
     */
    size_ipstr = strcspn(ipaddrandmask, "/");
    size_maskstr = strlen(ipaddrandmask)-size_ipstr-1;
    if ((size_ipstr>15)||(size_maskstr>2)){
        goto error;
    }
    
    /*
     * On récupere le string representant uniquement l'adresse IP
     * et on la convertie en binaire
     */ 
    tmp = strndup(ipaddrandmask, size_ipstr);
    if (convert_ipadress_to_binary(tmp, hostaddr)!=0){
        free(tmp);
        goto error;
    };
    
    free(tmp);
    
    /*
     * On récupere uniquement le masque au format string
     * puis on le convertit en entier
     */
    tmp = ipaddrandmask+size_ipstr+1;

    *cidr = calloc(1, sizeof(int));
    if (cidr==NULL) goto error;
    
    errno = 0;
    **cidr = strtol(tmp, NULL, 10);

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
        free(*cidr);
        free(hostaddr);
        free(mask);
        return -1;
}
