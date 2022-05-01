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

hashtable* new_hashtable(unsigned int size);
void free_hashtable(hashtable* table);

node* get_bucket(hashtable* table, size_t hash);
void add_item(hashtable* table, size_t hash, node* item);
void remove_item(hashtable* table, size_t hash, void* item);

#endif // PQDTLS_HASHTABLE_H