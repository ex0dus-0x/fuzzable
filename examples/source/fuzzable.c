#include <stdio.h>
#include <stdlib.h>

char *fuzz_me(char *buf, size_t size) {
    char buffer[2048];
    memcpy(buffer, buf, size);
    return NULL;
}

int main(int argc, char *argv[]) {
    fuzz_me(argv[1], sizeof(argv[1]);
    return 0;
}
