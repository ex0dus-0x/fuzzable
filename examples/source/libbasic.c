/*
 * libbasic.c
 *
 *      Basic sanity example for identifying fuzzable targets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 2048

typedef struct {
    int identifier;
    char contents[SIZE];
} obj_t;

// 1. We're consuming a buffer
// 2. That buffer flows into an unsafe call with memcpy
// 3. We do branch and that attributes to complexity
obj_t* vulnerable_parse_buf(char* buf, size_t size) {
    obj_t* obj = (obj_t *) malloc(sizeof(obj_t));
    if (obj == NULL) {
        return NULL;
    }
    obj->identifier = 100;

    // Hmmm....
    memcpy(obj->contents, buf, size);
    return obj;
}

void free_obj(obj_t* obj) {
    free(obj);
}

int not_so_vulnerable(obj_t* obj, int inc) {
    obj->identifier += inc;
    return 0;
}


