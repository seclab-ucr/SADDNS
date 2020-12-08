/*
    Utilities.
*/

#include "util.h"
#include "common.h"

/* Append a new link to an existent linked list. */
void link_append(struct link* link, struct link* new_link) {
    struct link* tmp = link;
    while (tmp->next != NULL)
        tmp = tmp->next;
    tmp->next = new_link;
}

/* Calculate lenghth of a linked list */
size_t link_length(struct link* link) {
    size_t ret = 1;
    struct link* tmp = link;
    while (tmp->next != NULL) {
        ret++;
        tmp = tmp->next;
    }
    return ret;
}

/* Free linked list */
void link_free(struct link* link) {
    struct link* tmp = link;
    struct link* tmp2 = tmp;
    if (tmp->next != NULL) {
        tmp = tmp->next;
        free(tmp2);
        tmp2 = tmp;
    }
    free(tmp);
}

/* Wrapper of malloc() and memset(). */
void* alloc_memory(size_t size) {
    void* ret = malloc(size);
    if (ret == NULL) {
#ifdef _DEBUG
        printf("alloc_memory: Fail to call malloc().\n");
#endif
        abort();
    }
    memset(ret, 0, size);
    return ret;
}

/* Sleep for the requested number of nanoseconds. */
void nsleep(long nsec) {
    struct timespec ts;

    if (nsec < 0)
        return;

    ts.tv_sec = 0;
    ts.tv_nsec = nsec;

    nanosleep(&ts, &ts);

    return;
}

/* Convert input string like "<ip_addr_1>:<ip_addr_2>:<ip_addr_3>" to an array,
   return the number of element in array. */
unsigned int strtok_ex(char** out, size_t outbuf_len, char* s, char* delim) {
    unsigned int i = 0;

    char* ele = strtok(s, delim);
    while(ele != NULL) {
        // Check memory.
        if (i * sizeof(char*) >= outbuf_len)
            break;

        out[i++] = ele;
        ele = strtok(NULL, ":");
    }

    return i;
}
