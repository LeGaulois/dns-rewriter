#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include <linux/types.h>
#include <linux/netfilter/nfnetlink_queue.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
#include <linux/ip.h>
#include <linux/udp.h>
/* only for NFQA_CT, not needed otherwise: */
#include <linux/netfilter/nfnetlink_conntrack.h>
//#include "/usr/include/internal.h"

#include <libnetfilter_queue/pktbuff.h>


#include "ntree_binary.h"
#include "iptools.h"
#include "tools.h"
#include "parser_tools.h"





void strtostr_replace(char* regex, char* replacement, char* search_in, char* write_to) {

	int tmp_result = 0;
	int len_write_to;
	int depart =0;
	int i=0;
	//On boucle sur l'ensemble des mots de X lettres
	//On suppose les taailles des chaines fixes, pour éviter le realloc

	//On suppose qu'il n'y a qu'un seul motif à remplacer
	
	strcpy(write_to,search_in);
	
	//On identifie le début de la regex grâce au "pointeur" depart 
	for(depart= 0; depart <strlen(write_to)-strlen(regex); depart++) {
		
		if(write_to[depart] == regex[0]) {
			for(int kl=1;kl<strlen(regex);kl++) {
				if(write_to[depart+kl] != regex[kl]) {
					tmp_result = 0;
					break;
				}
				else
					tmp_result = 1;
			}
		}
		if(tmp_result == 1) {
			break;
		}
	}
	// on parsdésormais du principe que la ergex & le remplacemet n'ont pas la même taille
	// donc on va : 1 - décaler toutes les cases à partir de la fin, de X case vers la gauche/droite fct de la diff des regex
	// 				2 - X va être égal à la différence de lg entre regex & replacement

	int diff = strlen(regex) - strlen(replacement);
	
	len_write_to = strlen(write_to) + 1; // Pour prendre en compte le '\0'

	if(diff < 0) { // replacement plus long que regex
		for (i = len_write_to;i>=depart;i--) {
			write_to[i-diff] = write_to[i];
			
		}
	}
	else
	{ //replacement plus court que regex
		for (i = depart+strlen(replacement); i<strlen(write_to)-diff;i++) {
			write_to[i]  = write_to[i+diff];
		}
		write_to[i] = '\0';
	}
	
	
	for(i=0; i<strlen(replacement); i++) {
		write_to[depart+i] = replacement[i];
	}
}


void strtodns_qfmt(char* finalrewrite, char* to_insert) {
	char *pt = NULL;
	pt = finalrewrite;

	int len,i,count,c,k;
	count = 0;
//On compte le nombre de caractere delimiteurs
	for(int j =0;j<strlen(finalrewrite);j++) {
		if(finalrewrite[j] == 0x2E) //0x20 espace ; 0x2E .
		   count++;
	}
	k = 0;

	for(c=0;c<=count;c++) {
		len = strcspn(pt,".");
		to_insert[k] = (char)len;
		k++;
		
		for (i=0;i<len; i++) {
			to_insert[k] = pt[i];
			k++;
		}

		pt += len +1;
	}
		to_insert[k] = 0x00;
}

int get_len_qfmt(char* to_insert) {
	int i = 0;
	do {
	    i++;
	} while (to_insert[i] != 0x00);
	return i;
}


