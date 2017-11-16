#include "list.h"
#ifndef HASH_H
#define HASH_H

#define MAX_CASE_HASHTABLE 64
#define MD5_HASH_SIZE 16

typedef struct hashtable hashtable;

struct hashtable {
    int     nbentries;
    int     size;
    int     (*free_data)(void **data);
    int     (*compare_data)(void *d1, void *d2);
    list    *entries[];
};

int hashtable_init(hashtable **ht, int size, int(*free_data)(void **data), int(*compare_data)(void *d1, void *d2));

hashtable* hashtable_init_from_file(int size, int(*free_data)(void **data),
        int(*compare_data)(void *d1, void *d2), char*filename);
int hashtable_free(hashtable **ht);
int do_hash(char *str, unsigned char *digest);
int get_hashtable_position_from_digest(hashtable *ht,
    unsigned char *digest, int sizeofhash);
void* hashtable_get_element(hashtable *ht, char *cible);
int hashtable_add_element(hashtable *ht, char *str, void *data);


#endif



