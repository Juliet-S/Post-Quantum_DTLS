#include <stdlib.h>
#include <stdio.h>

#if WIN32
#else
 #include <memory.h>
#endif

#include "common/hashtable.h"
#include "common/debug.h"

hashtable* hashtable_new(unsigned int size)
{
    hashtable* table = calloc(1, sizeof(hashtable));
    node** nodes = calloc(size, sizeof(node*));
    table->data = nodes;
    table->size = size;

    return table;
}

void hashtable_free(hashtable* table)
{
    for (size_t i = 0; i < table->size; i++) {
        node* current = table->data[i];
        if (current == NULL) {
            continue;
        }

        node* prev;
        while (current != NULL) {
            prev = current;
            current = current->next;
            table->free_func(prev);
            free(prev);
        }
    }

    free(table->data);
    free(table);
}

node* hashtable_get(hashtable* table, size_t hash)
{
    return table->data[hash % table->size];
}

void hashtable_add(hashtable* table, size_t hash, node* item)
{
    node* current = table->data[hash % table->size];
    if (current == NULL) {
        table->data[hash % table->size] = item;
        return;
    }

    while (current->next != NULL) {
        current = current->next;
    }

    current->next = item;
}

void hashtable_remove(hashtable* table, size_t hash, void* item)
{
    node* current = table->data[hash % table->size];
    if (current == NULL) {
        dprint("Failed to remove item\n");
        return;
    }

    if (current->data == item) {
        table->free_func(item);
        table->data[hash % table->size] = NULL;
        return;
    }

    node* previous;
    while (current->next != NULL) {
        previous = current;
        current = current->next;

        if (current->data == item) {
            previous->next = current->next;
            table->free_func(item);
            break;
        }
    }
}