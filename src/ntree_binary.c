#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include "list.h"
#include "ntree_binary.h"
#include <arpa/inet.h>
#include "tools.h"
#include "iptools.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/**
 * Privates functions
 */
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
static int ntree_node_add_data(ntree_node *node, void *data, int strict);
static void ntree_node_force_add_data(ntree_node *node, 
        void *data, int strict);


/**
* NTREE_NODE_INIT
* Fonction d'initialisation d'un noeud
* @root: pointeur vers le noeud racine
* @parent: pointeur vers le noeud pere
* @data: pointeur sur la data
*
* Valeurs de retour:
* @pointeur sur la nouvelle structure si success
* @NULL sinon
*/
static ntree_node* ntree_node_init( 
    ntree_root *root, ntree_node *parent,
    void *data)
{
    ntree_node *tb = NULL;
    unsigned int stride; 
    
    stride = root->stride;
    
    /*
     * Initialisation du à la flexibla array (child[])dans la struct
     */
    tb = malloc(1*sizeof(ntree_node) + 
                pow(2,stride)*sizeof(ntree_node*));
    
    if ( tb == NULL ){
        fprintf(stderr,"Erreur de creation de la truct ntree: %s.",
            strerror(errno));
        return NULL;
    }
    
    tb->root        = root;
    tb->parent      = parent;
    tb->data        = data;
    tb->strict      = 0;
    memset(tb->child, 0, pow(2,stride)*sizeof(ntree_node*));
    
    return tb;
}


/**
* NTREE_ROOT_INIT
* Fonction d'initialisation du noeud root
* @stride: valeur qui definit indirectement le nombre
* de fils de chaque noeud de l'arbre (2^stride)
* @free_data: fonction de liberation des data
* contenu dans les noeuds
* 
* Valeurs de retour:
* @pointeur sur la nouvelle structure si success
* @NULL sinon
*/
ntree_root* ntree_root_init(unsigned int stride, 
                            int (*free_data)(void *data))
{
    ntree_root *tr = NULL; 
    
    /*
    * On controle la valeur du stride transmise afin que 
    * celle-ci ne depasse pas la limite de la struct 
    * (2 bits) soit max==3
    */

    if ( stride>3 ){
        fprintf(stderr, "Valeur de stride trop élevée (Max: 4).");
        return NULL;
    }
    
    tr = malloc(1*sizeof(ntree_root));
    
    if ( tr == NULL ){
        fprintf(stderr,"Erreur de creation de la truct ntree: %s.",
            strerror(errno));
        return NULL;
    }
    
    memset(tr, 0, sizeof(ntree_root));
    tr->stride      = stride;
    tr->free_data   = free_data;
    tr->root        = ntree_node_init(tr, NULL, NULL);
    
    if (tr->root == NULL) {
        ntree_root_free(&tr);
        fprintf(stderr,"Erreur de création du root binary\n");
        return NULL;
    }
    
    return tr;
}


/**
* NTREE_NODE_FORGET_CHILD
* Fonction permettant de supprimer la reference
* au noeud "node" dans le noeud parent
* 
* Valeurs de retours
* @-1: le noeud n'a pas été trouvé chez le père --> grave
* @0: OK
* @1: le noeud n'a pas de pere
*/
static int ntree_node_forget_child(ntree_node *node){
    int i,nbchild;
    
    nbchild = pow(2,node->root->stride);
    
    if (node->parent == NULL) return 1;
    
    for (i=0; i<nbchild ; i++)
    {
        if ( node->parent->child[i] == node )
        {
            node->parent->child[i] = NULL;
            return 0;
        }
    }
    return -1;
}


/**
* NTREE_NODE_DELETE
* Supprime un noeud d'un arbre binaire
*   - si ce noeud posséde encore des fils, la fonction
*     supprime uniquement la data
*   - sinon, la data est supprime, la reference au noeud
*     sur le pere est supprimée
*
*   Valeurs de retour
*   @0: SUCCESS
*   @-1 sinon
*/
static int ntree_node_delete(ntree_node **node){
    int i = 0, max=0;
    uint8_t all_child_free = 1, ret=0;
    
    max     = (*node)->root->stride;
    
    /*
     *On verifie si tous les fils sont libere
     */ 
    for (i=0; i<max;i++){
        if ( (*node)->child[i] != NULL){
            all_child_free = 0;
            break;
        }
    }
    
    /*
    * Dans tous les cas on libere la data contenu
    * dans le noeud
    */
    if ( (*node)->root->free_data((*node)->data) !=1){
        fprintf(stderr,"Erreur de libération de la data: \
        %s\n",strerror(errno));
        ret=-1;
    }
    
    (*node)->data = NULL;
    (*node)->strict =0;
    
    /*
    * Si tous nos fils sont morts, alors on peut
    * se suicider. On supprime avant notre reference
    * dans le table des fils de notre pere 
    */
    
    if ( all_child_free == 1){
        if (ntree_node_forget_child(*node) !=0) ret=-1;
        free(*node);
    }
    return ret;
}


/**
* NTREE_NODE_GET_SON_BITS
* renvoie le fils par rapport à sa position exprimé en binaire
*/
static ntree_node* ntree_node_get_son(ntree_node *parent, uint8_t position){

    if(parent==NULL) return NULL;
    if ( position > pow(2,parent->root->stride)-1){
        fprintf(stderr,"Invalid child number %d\n", position);
        return NULL;
    }
    return parent->child[position]; 
}



/**
 * NTREE_NODE_GET_FIRST_SON
 * Renvoie le premier fils disponible dans la liste
 * Si return == NULL, alors cela signifie que le noeud
 * n'a plus de fils
 */
static ntree_node* ntree_node_get_first_son(ntree_node *parent){
    int i=0, max=0;
    
    if (parent==NULL) return NULL;
    max = pow(2,parent->root->stride);
    
    for (i=0; i<max; i++){
        if( parent->child[i]!=NULL){
            return parent->child[i];
        } 
    }
    return NULL;
}


/**
 * NTREE_NODE_GET_LAST_SON
 * Renvoie le dernier fils de la branche ayant pour origine
 * @parent. Les fils sont parcourus respectivement de
 * gauche a droite dans l'arbre. Le pointeur renvoye ne
 * correspond donc pas forcement au fils le plus profond
 * dans l'arbre.
 */
static ntree_node* ntree_node_get_last_son(ntree_node *parent){
    ntree_node *actual = NULL, *next = NULL;
    
    if (parent == NULL) return NULL;
    actual = parent;
    
    while(1){
        next = ntree_node_get_first_son(actual);
        
        /*
         * Différents cas:
         * - le dernier noeud n'a plus de fils
         * - le parent fourni n'a plus de fils. On ne peut pas renvoyer
         *   actual car le pere doit etre different du fils. On renvoie
         *   donc NULL
         */
        if ((next==NULL )&&(actual != parent)) return actual;
        if ((next==NULL )&&(actual == parent)) return NULL;
        actual = next;
    } 
}


/**
 * NTREE_ROOT_FREE
 * Supprime un arbre binaire
 *
 * TODO: Ameliorer la suppression, on parcourt l'arbre depuis le root
 * à chaque fois, il faudrait mettre en place une variable statique
 * dans get last_son peut etre ?
 */
int ntree_root_free(ntree_root **root){
    ntree_node *parent = NULL, *son = NULL;
    int ret = 0;
    
    while( (parent=ntree_node_get_first_son((*root)->root))!=NULL){
        while ((son=ntree_node_get_last_son(parent))!=NULL){
            if( ntree_node_delete(&son)!= 0) ret = -1;
        }
        if (ntree_node_delete(&parent) != 0) ret =-1;
    }
    
    if (ntree_node_delete(&(*root)->root) != 0) ret=-1;
    free(*root);
    
    return ret;
}


/**
 * NTREE_NODE_ADD_DATA
 * Ajoute une donnée à un noeud existant
 *
 *      @node: pointeur sur le noeud
 *      @data: pointeur sur la data
 *      @strict: valeur strict de la nouvelle data
 *
 * Valeurs de retours 
 * @-1: suppresion impossible
 * @0: SUCCESS
 */
static int ntree_node_add_data(ntree_node *node, void *data, int strict)
{

    if ((node->strict)&&(node->data!=NULL)) return -1;
    
    if ((node->data!=NULL)&&(node->root->free_data!=NULL)){
        node->root->free_data(node->data);
    }
    
    node->data = data;
    node->strict = strict;
    return 0;
}

/**
 * NTREE_NODE_FORCE_ADD_DATA
 * Ajoute une donnée à un noeud existant
 *
 *      @node: pointeur sur le noeud
 *      @data: pointeur sur la data
 *      @strict: valeur strict de la nouvelle data
 *
 */
static void ntree_node_force_add_data(ntree_node *node, 
        void *data, int strict)
{
    
    if ((node->data!=NULL)&&(node->root->free_data!=NULL)){
        node->root->free_data(node->data);
    }
    
    node->data = data;
    node->strict = strict;
}


/**
 * NTREE_NODE_GOTO_ADDRESS
 * Fonction permettant d'accéder à un noeud via son adresse
 *
 * Parametres
 *  @root: racine de l'arbre
 *  @address: adresse du noeud
 *  @nb_significant_bits: nombre de bits significatifs
 *  @force: force la creation des noeuds inexistant
 *
 * Valeurs de retour:
 * @NULL: FAILED
 * @PTR: pointeur sur le noeud
 */
static ntree_node* ntree_node_goto_address(ntree_root *root, 
        uint32_t address, int nb_significant_bits, uint8_t force)
{
    uint8_t node_number = 0;
    int nbnodes, i, position;
    ntree_node *parent = NULL, *choice=NULL;
    

    /*
     * On ne peut atteindre qu'un noeud dont l'adresse 
     * est codé sur un multiple du nombre de fils
     * sur un noeud
     */
    if (nb_significant_bits%root->stride != 0) return NULL;
    
    nbnodes = nb_significant_bits/root->stride;
    
    parent=root->root;
    position=0;
    
    /*
     * On parcours l'arbre jusqu'à atteindre le bon noeud
     * si un noeud n'existe pas sur le parcours, on le crée
     */
    for (i=0;i<nbnodes;i++){
        node_number = get_n_bits_from_uint32t(address, position, root->stride);
        choice = ntree_node_get_son(parent, node_number);
        
        if (choice==NULL){
            if (force) parent = ntree_node_init(root, parent, NULL);
            else return NULL;
        }
        else parent = choice;
        
        /*
         * On ajoute le child crée dans le tableau des child du pere
         */
        parent->parent->child[node_number] = parent;
        position += root->stride;
    }
    
    return parent;
}


/**
 * NTREE_NODE_ADD_DATA_ONMULTIPLE_CHILD
 * Ajoute une data sur potentiellement plusieurs fils d'un noeud
 * Utile dans le cas où stride > 1
 * Cette fonction ne prend en compte que le dernier noeud.
 *
 *  @previous: noeud parent
 *  @addr: adresse du fils
 *  @nb_significant_bits: nombre de bits significatif de l'adresse du fils
 *  @position: position actuelle dans l'adresse globale.
 *             doit correspondre à l'adresse du dernier noeud
 *  @data: donnee à ajouter
 *  @datasize: taille de la donnée
 *
 * Valeurs de retour:
 *  @0: SUCCESS
 *  @-1: ERROR
 */
static int ntree_node_add_data_onmultiple_child(ntree_node *previous,
    uint32_t addr, int nb_significant_bits, int position, 
    void *data, size_t datasize)
{
    ntree_root *root = NULL;
    ntree_node *parent = NULL, *choice=NULL;
    int i, nbchoice=0, max, fixe, position_in_stride, already_add=0;
    uint32_t cp_addr;
    void *cpy_data = NULL;
    
    root = previous->root;
    nbchoice = nb_significant_bits-position;    
    max = pow(2, root->stride - nbchoice);
    
    fixe= 0;
    cp_addr = addr << position;
    position_in_stride = 0;
    
    /**
     * On determine la valeur min du fils
     * Par exemple si root->stride = 3, on a au max 8 fils
     * Si on a seulement 1 bit de fixe on sait que la 
     * plus petite valeur possible sera 2^2 soit 4
     * @nbchoice = nombre de bits fixes
     * @max = nombre iteration possibles
     */
    for(i=0; i<nbchoice; i++){
        if (cp_addr&1) fixe += pow(2, root->stride-i);
        cp_addr = cp_addr <<1;
        position++;
        position_in_stride++;
    }
        
    parent = previous; 
    for (i=0; i<max; i++){
        position = fixe +i;
        choice = ntree_node_get_son(parent, position);
        
        /*
         * Ce noeud contient deja une valeur qui est stricte
         * càd dont l'adresse tombe exactement sur l'adresse
         * d'un noeud
         */
        if ((choice != NULL) && (choice->strict==1)) continue;
            
        /*
         * On doit recopier la valeur de data pour la placer
         * dans le noeud dans le cas ou celle ci aurait
         * deja ete place sur un autre noeud
         * Si on ne fait pas cela, on obtiendra un SEGFAULT
         * lors de la suppresion de l'arbre
         * free succesif sur un pointeur deja dereferencer par
         * un autre noeud
         */
        if (already_add==1){
            if ((cpy_data = malloc(1*datasize))==NULL) return -1;
            memcpy(cpy_data,data,datasize);
        }
        else {
            cpy_data = data;
            already_add = 1;
        }
            
        if (choice==NULL){
            choice = ntree_node_init(root, parent,cpy_data);
            if(choice==NULL) return -1;
            parent->child[position] = choice;
        }
        
        else if (choice->data==NULL) choice->data = cpy_data;
        else if (choice->strict==0){
            root->free_data(choice->data);
            choice->data = cpy_data;
        }
            choice->strict =0;
    }
    return 0;
}


/**
 * NTREE_ROOT_ADD_DATA
 * Ajoute une donnée à un arbre binaire
 *
 *  @root: racine de l'arbre
 *  @addr: adresse du fils
 *  @nb_significant_bits: nombre de bits significatif de l'adresse du fils
 *  @data: donnee à ajouter
 *  @datasize: taille de la donnée
 *
 * Valeurs de retour:
 *  @0 SUCCESS
 *  @-1: ERROR
 */
int ntree_root_add_data(ntree_root *root, uint32_t addr,
    int nb_significant_bits, void *data, size_t datasize)
{
    uint8_t node_number = 0;
    int position = 0, nbchoice=0, reste;
    ntree_node *parent = NULL, *choice=NULL;
    
    
    reste = nb_significant_bits%root->stride;
    if (reste!=0){
        position = nb_significant_bits-reste;
    }
    else if(nb_significant_bits!=0)position = nb_significant_bits - root->stride;
    
    parent = ntree_node_goto_address(root, addr, position, 1);
    /**
     * Cas ou le LPM peut nous renvoyer 2 choix.
     * Exemple: stride=2, address= 01001*
     * La troisieme iteration de boucle nous renverra 1
     * comme node_number. Donc 2 choix possibles: 10 et/ou 11
     * Dans ce cas on utilise la variable @strict
     * si la variables est positionne, on considere que la valeur
     * du noeud ne peut etre changé (cas ou le netaddr est 010010
     * par exemple). Dans ce cas on ecrite uniquement sur le noeud
     * libre ou dont le @strict est à 0.
     * Si les 2 noeuds sont occupées, on renvoie une erreur 
     */
    if ((nbchoice = nb_significant_bits-position) != root->stride){
            ntree_node_add_data_onmultiple_child(parent,addr, 
            nb_significant_bits, position, data,datasize);
    }
    
    else {
        
        node_number = get_n_bits_from_uint32t(addr, position, root->stride);
        choice = ntree_node_get_son(parent, node_number);
        
        if (choice==NULL){
            choice = ntree_node_init(root, parent,data);
            parent->child[node_number] = choice;
        }
        else if (choice->data==NULL) choice->data = data;
        else if (choice->strict==0){
            root->free_data(choice->data);
            choice->data = data;
        }
        else return -1;
        
        choice->strict = 1;
    }
    

    return 0;
    
}


/**
 * NTREE_ROOT_LOOKUP
 * Fonction de recherche du LPM (Longest Prefix Match)
 * dans un arbre binaire à partir d'une adresse.
 * Ce type de fonction est utilise dans les tables de routage
 * pour déterminer la route la plus précise pour une adresse
 * IP de destination.
 * Cette fonction est donc différente de @NTREE_NODE_GOTO_ADDRESS
 * qui elle renvoie la position un pointeur sur le noeud
 * ayant cette adresse.
 *
 * Parametres
 * @root: pointeur sur la racine de l'arbre
 * @addr: entier sur 32 bits
 *
 * Valeur de retour
 * @PTR: void pointeur sur l'adresse du noeud ayant le plus
 *       long prefixe en commun avec @addr et dont la data
 *       n'est pas NULL
 */
void* ntree_root_lookup(ntree_root *root, uint32_t addr){
    uint8_t node_number; 
    int i=0, max_iteration, position = 0;
    ntree_node *parent = NULL, *son=NULL, *last_no_null=NULL;
    
    parent = root->root;
    max_iteration = 32 / root->stride; 
    
    for (i=0;i<max_iteration;i++){
        
        node_number = get_n_bits_from_uint32t(addr, position, root->stride);
        son = ntree_node_get_son(parent, node_number);

        
        if (!son){
            if(last_no_null) return  last_no_null->data;
            return NULL;
        }
        if(son->data) last_no_null = son;
        parent = son;
        position += root->stride;
    }
    return parent->data;
}



ntree_root* ntree_root_init_from_file(char *filename, int (*free_data)(void *data))
{
    ntree_root *root=NULL;
    int fd;
    
    if(filename==NULL) return NULL;
    
    root = ntree_root_init(2, free_data);    
    fd = open(filename, O_RDONLY);
    
    /*
     * Peuplement de l'arbre à partir d'un fichier
     */
    if(fd<0){
        fprintf(stderr, "Erreur lors de l'ouverture: \
             %s. \n", strerror(errno));
        ntree_root_free(&root);
        return NULL;
    }
    
    lecture_fd_rangefile(fd, root);
    
    if(close(fd)<0){
        fprintf(stderr, "Erreur lors de la fermeture: %s. \n", strerror(errno));
    }
    
    return root;
}
