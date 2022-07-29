#ifndef PQDTLS_HASHTABLE_H
#define PQDTLS_HASHTABLE_H

typedef struct node_t {
    void* data;
    struct node_t* next;
} node;

typedef struct hashtable_t {
    void* (*free_func)(void*);
    size_t size;
    node** data;
} hashtable;

hashtable* hashtable_new(unsigned int size);
void hashtable_free(hashtable* table);

node* hashtable_get(hashtable* table, size_t hash);
void hashtable_add(hashtable* table, size_t hash, node* item);
void hashtable_remove(hashtable* table, size_t hash, void* item);

#endif // PQDTLS_HASHTABLE_H