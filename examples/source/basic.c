#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *vulnerable_parse_buf(char *buf, size_t size) {
    // Hmmm....
    char buffer[2048];
    memcpy(buffer, buf, size);
    return NULL;
}

void also_potentially_vulnerable(char *filename) {
    FILE *fd = fopen(filename, "r");
    fclose(fd);
}

int not_so_vulnerable(int test) {
    return test + 1;
}

int main(int argc, char *argv[]) {
    vulnerable_parse_buf(argv[1], sizeof(argv[1]));
    not_so_vulnerable(12);
    return 0;
}
