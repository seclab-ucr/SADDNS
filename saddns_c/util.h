/*
    Utilities.
*/

#ifndef _GENERIC_H_
#define _GENERIC_H_

#include "common.h"

struct link {
    struct link* next;
};

void link_append(struct link* link, struct link* new_link);

size_t link_length(struct link* link);

void link_free(struct link* link);

void* alloc_memory(size_t size);

void nsleep(long nsec);

unsigned int strtok_ex(char** out, size_t outbuf_len, char* s, char* delim);

#endif // !_GENERIC_H_
