#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <openssl/md5.h>
#include <errno.h>
#include "list.h"
#include "dns_translation.h"
#include "hash.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>



/**
 * HASHTABLE_INIT
 * Initialise une hashtable. Chaque entree de la hashtable sera une liste
 * permettant de gérer les éventuelles collisions induite par la fonction
 * de hashage.
 *
 * Paramètres
 *  @ht: adresse du pointeur sur la hashtable
 *  @size: taille de la hashtable
 *  @free_data: pointeur sur la fonction de suppresion des données
 *              contenues dans la hashtable
 *  @compare_data: pointeur sur la fonction de comparaison de données
 *              dans la hashtable
 *
 * Valeurs de retour
 * 0 -> SUCCESS
 * -1 -> ERREUR
 */
int hashtable_init(hashtable **ht, int size, int(*free_data)(void **data),
        int(*compare_data)(void *d1, void *d2))
{
    *ht = NULL;
    *ht = malloc(1*sizeof(hashtable) + size*sizeof(list*));
    
    if (*ht==NULL) return -1;
    memset(*ht, 0, 1*sizeof(hashtable) + size*sizeof(list*));
    (*ht)->nbentries = 0;
    (*ht)->size = size;
    (*ht)->free_data = free_data;
    (*ht)->compare_data = compare_data;
    return 0;
}



hashtable* hashtable_init_from_file(int size, int(*free_data)(void **data),
        int(*compare_data)(void *d1, void *d2), char*filename, uint8_t type)
{
    hashtable *ht = NULL;
    int ret;
    ret = hashtable_init(&ht, 128, &dns_translation_free,
     &dns_translation_compare_query);
     
    if ( ret !=0 ){
        fprintf(stderr,"Erreur d'allocation de la hashtable\n'");
        return NULL;
    }
    
    ret = hashtable_complete_from_file(ht, filename, type);
    
    if ( ret !=0){
        fprintf(stderr,"Erreur d'import du fichier\n");
        hashtable_free(&ht);
        return NULL;
    }   
    
    return ht;
}


/**
 * HASHTABLE_FREE
 * Fonction de suppresion d'une hashtable
 *
 * Parametres
 * @ht: adresse du pointeur sur la structure hashtable
 *
 * Valeurs de retour
 * 0 -> SUCCESS
 * sinon -> ERROR
 */
int hashtable_free(hashtable **ht)
{
    int i=0, max, ret=0;
    
    if (*ht==NULL) return -1;
    max = (*ht)->size;
    
	for(i=0;i<max;i++){
	     if (list_destroy( &((*ht)->entries[i]))!= 0) ret = -1;
    }
	free(*ht);
	return ret;
}


/**
 * DO_HASH
 * Génération d'un hash à partir d'un string
 * 
 * Paramètres
 * @str: string à hasher
 * @digest: valeur du hash 
 *
 * Valeurs de retour
 * -1 -> ERREUR
 *  0 -> SUCCESS
 */
int do_hash(char *str, unsigned char *digest) 
{
	MD5_CTX context;
	
	if (MD5_Init(&context) != 1) goto error;
	if (MD5_Update (&context, str, strlen(str)) != 1) goto error;
	if (MD5_Final(digest, &context) !=1) goto error;
	return 0;
	
	error:
	    return -1;
}


/**
 * GET_HASTABLE_POSITION_FROM_DIGEST
 *
 * Retourne la position dans la table de hashage
 * par rapport à un digest
 * La valeur de retour sera donc comprise entre 0 et (@ht->size) - 1
 *
 * Paramètres
 * @ht: pointeur sur la table de hashage
 * @digest: char 
 * @sizeofhash: taille du hash en octet.
 *          Par exemple pour un hash en MD5, on mettra
 *          sizeofhash=5 
 *
 * Valeurs de retour
 * -1 -> ERREUR
 * position sinon
 */
int get_hashtable_position_from_digest(hashtable *ht,
    unsigned char *digest, int sizeofhash)
{
    if((digest==NULL)||(sizeofhash==0)) return -1;
	int hashsum = 0;
	
	for (int i=0;i<sizeofhash;i++) {
		hashsum += digest[i];
	}
	return hashsum % ht->size;
}


/**
 * HASHTABLE_GET_ELEMENT
 * Récupére un élément dan sune table de hashage
 *
 * @ht: table de hashage
 * @cible: str a rechercher
 * @cible2: 2nde str a rechercher
 *
 * Valeurs de retour
 * @NULL: la cible n'existe pas dans la table de hashage
 * @PTR: pointeur sur la data correspondant a la @cible
 *  
 */
void* hashtable_get_element(hashtable *ht, char *cible, char *cible2){
    unsigned char *digest = NULL;
    int position;
    list *l = NULL;
    element *el = NULL;
    
    digest = calloc(MD5_HASH_SIZE, sizeof(char));
    if(digest==NULL) return NULL;
    
    if (do_hash(cible, digest) != 0) return NULL;
    position = get_hashtable_position_from_digest(ht, digest, MD5_HASH_SIZE);
    free(digest);

    if (position ==-1) return NULL;
    
    l = ht->entries[position];
    /*
     * L'utilisation de cible2 permet de diversifier 
     * les critères de recherche dans la hashtable.
     * Pour la Hash_Q, on recherchera dans la HT&liste via la query 
     * Pour la Hash_R, on recherchera dans la HT via le Transaction ID
     * 				      et dans la liste via la query
     * 
     * @cible identifiera toujours le paramètre de HASH.
     */
      
    if(cible2 != NULL) el = list_get_element_by_data(l, cible2);
    if(cible2 == NULL) el = list_get_element_by_data(l,cible);
    
    if (el==NULL) return NULL;
    return el->data;
}


/**
 * HASHTABLE_ADD_ELEMENT
 * Ajoute un élémenet à une hashtable
 * 
 * Parametres
 * @ht: pointeur sur la table de hashage
 * @str: string de recherche
 * @data: donnée dans la hashtable
 *
 * Valeur de retour
 *  0 -> OK
 * -1 -> ERREUR
 *  1 -> DATA deja presente
 */
int hashtable_add_element(hashtable *ht, char *str, void *data){
    unsigned char *digest = NULL;
    int position;
    list *l = NULL;
    
    digest = calloc(MD5_HASH_SIZE, sizeof(char));
    if(digest==NULL) return -1;
    
    if (do_hash(str, digest) != 0) return -1;
    position = get_hashtable_position_from_digest(ht, digest, MD5_HASH_SIZE);
    free(digest);
    
    if (position ==-1) return -1;
    
    l = ht->entries[position];
    if (l==NULL){
        ht->entries[position] = list_init(ht->free_data, ht->compare_data);
        l = ht->entries[position];
        if(l==NULL) return -1;
    }
    ht->nbentries += 1;
    
    return list_uniq_rpush(l, data); 
}
