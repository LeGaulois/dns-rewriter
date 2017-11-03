#ifndef NTREE_BINARY_H_INCLUDED
#define NTREE_BINARY_H_INCLUDED


typedef struct ntree_node ntree_node;
typedef struct ntree_root ntree_root;


/**
 * STRUCT NTREE_NODE
 * Structure definisaant un noeud d'un arbre binaire
 *   - root: pointeur vers la racine de l'arbre
 *   - parent: pointeur sur le noeud parent
 *   - data: data contenu dans le noeud
 *   - child[]: ensemble des fils. flexible array dont la taille
 *     dependra de la valeur de stride
 */
struct ntree_node {
    ntree_root      *root;
    ntree_node      *parent;
    void            *data;
    unsigned int    strict:1;
    ntree_node      *child[];
};


/**
 * STRUCT NTREE_ROOT
 * Structure definisaant le noeud racine d'un arbre binaire
 *   - stride: valeur qui definit indirectement le nombre
 *     de fils de chaque noeud de l'arbre (2^stride)
 *   - free_data: fonctio de liberation des data contenu
 *     dans tous les noeuds des arbres.
 *     Cela implique que tous les noeuds contiennent des data
 *     de meme nature
 *   - reserved: glag permettant d'indiquer si la data peut
 *     etre reecrite
 *   - child[]: ensemble des fils. flexible array dont la taille
 *     dependra de la valeur de stride
 */
struct ntree_root {
    unsigned int    stride:2;
    int             (*free_data)(void *data);
    ntree_node      *root;
};



/*
 * Privates functions
 
static ntree_node* ntree_node_init( 
    ntree_root *root, ntree_node *parent,
    void *data);
static int ntree_node_forget_child(ntree_node *node);
static int ntree_node_delete(ntree_node **node);
static ntree_node* ntree_node_get_son(ntree_node *parent, uint8_t position);
static ntree_node* ntree_node_get_first_son(ntree_node *parent);
static ntree_node* ntree_node_get_last_son(ntree_node *parent);
static int ntree_node_add_data(ntree_node *node, void *data, int strict);
static int ntree_node_add_data_onmultiple_child(ntree_node *previous,
    uint32_t addr, int nb_significant_bits, int position, 
    void *data, size_t datasize);
static ntree_node* ntree_node_goto_address(ntree_root *root, 
        uint32_t address, int nb_significant_bits, uint8_t force);
*/


/*
 * Public functions
 */
ntree_root* ntree_root_init(unsigned int stride, 
                            int (*free_data)(void *data));
int ntree_root_add_data(ntree_root *root, uint32_t addr, int nb_significant_bits, void *data, size_t datasize);
int ntree_root_free(ntree_root **root);
void* ntree_root_lookup(ntree_root *root, uint32_t addr);

#endif
