#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <openssl/md5.h>
#include "../include/hash.h"
#include "../include/list.h"


dns_t* dns_struct_init(){
    dns_t *dns = NULL;
    
    dns = calloc(1, sizeof(dns_t));
    if(dns==NULL){
       return dns;
    }
    
    dns->query      = NULL;
    dns->rewrited   = NULL;
    dns->query      = calloc(35, sizeof(char));
    dns->rewrited   = calloc(35, sizeof(char));
    return dns;
}

int free_dnsdata(void *dnsdata) 
{
    free(((dns_t*)dnsdata)->query);
    free(((dns_t*)dnsdata)->rewrited);
    free(dnsdata);

    return 0;
}

int compare_dnsdata(void *dns1, void *dns2) 
{
	if(memcmp((dns_t*)dns1,(dns_t*)dns2,sizeof(dns_t)) == 0) {
		return 0;
	}
	else return 1;
}


dns_t* get_dns_by_query(list **hashtable, char* init_query) 
{
   unsigned char *hash_md = NULL;
   int value_in_hashtable = 0;
   hash_md = calloc(16,sizeof(char));
   
   do_hash(init_query,hash_md);
   value_in_hashtable = get_val_from_digest(hash_md);
   
   list *current_pl=NULL;
   current_pl = *(hashtable+value_in_hashtable);
   
   if((void *)current_pl != NULL) {
     element *current_elem_inpl = NULL;
     current_elem_inpl = current_pl->first; 

     do {
       if(strcmp(((dns_t *)current_elem_inpl->data)->query,init_query) == 0) {
          return (dns_t *)current_elem_inpl->data;
       }
        current_elem_inpl = current_elem_inpl->next;
     } while (current_elem_inpl != NULL);
  }
  else {
  	return NULL;
  }
  free(hash_md);
}

//on prends un pointeur sur int en entier, donc à l'appel de la fonction on aura juste besoin de l'adrs de la 1ère case du tableau renvoyée par "digest"
void do_hash(char *str, unsigned char *digest) 
{
	MD5_CTX context;
	MD5_Init(&context);
	MD5_Update (&context, str, strlen(str));
	MD5_Final(digest, &context);
}

int get_val_from_digest(unsigned char *digest)	
{
	int hashsum = 0;
	for (int i=0;i<16;i++) {
		hashsum += digest[i];
	}
	return hashsum % MAX_CASE_HASHTABLE;
}


void gen_hash_table(list **hashtable)
{
 	//Création des variables
   char string_raw[64] = ""; 
   unsigned char *hash_md = NULL;
   char dns_entry_cfgfile[] = "../dns-rewriter-master/dnsentry.cfg";
   int value_in_hashtable = 0;
   hash_md = calloc(16,sizeof(char)); 
	
   //Ouverture du fichier
   FILE* fd = NULL;
   fd = fopen(dns_entry_cfgfile, "r");
   if(fd != NULL && hash_md != NULL) {
     while (fgets(string_raw,64,fd) != NULL) {
       if (string_raw[0] == '#') {
         continue;
       }
       dns_t *dns_element = dns_struct_init();
       if( dns_element != NULL) { 
          sscanf(string_raw,"%s\t%s", dns_element->query,dns_element->rewrited); 
          do_hash(dns_element->query,hash_md);
          value_in_hashtable =  get_val_from_digest(hash_md); 
	      
          if(*(hashtable + value_in_hashtable) == NULL){
             list *l = list_init(free_dnsdata,compare_dnsdata);
             list_lpush(l,dns_element);	      
             *(hashtable + value_in_hashtable) = l;     
          }
          else {
             list_lpush(*(hashtable + value_in_hashtable),dns_element);
         }
      }
      else printf("DNS STRUCT FAILED");
    }
   }
   else {
      fprintf(stderr,"Error in hash.c -gen_hash_table- #3");
   }
   //libération de la mémoire
   free(hash_md);
   fclose(fd);
}


void free_hashtable (list **hashtable)
{
	for(int i=0;i<MAX_CASE_HASHTABLE;i++){
	   if(hashtable[i] != NULL) {
	     list_destroy(&hashtable[i]);

    	   }
    	   free(hashtable[i]);
    	}
	free(hashtable);
}
