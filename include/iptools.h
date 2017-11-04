#ifndef  IPTOOLS_H
#define  IPTOOLS_H

int convert_ipadress_to_binary(char *ipaddress, uint32_t *binaryaddr); 
int convert_netmask_to_binary(int netmaskcidr, uint32_t *binarynetmask);
uint32_t* get_network_address(uint32_t hostaddr, uint32_t mask);
char* uint32_t_to_char(const uint32_t binary_number);
int get_networkaddress_and_mask_from_char(
    char *ipaddrandmask, uint32_t **netaddr, int **cidr);
uint32_t uint32_t_invert(uint32_t addr);

#endif
