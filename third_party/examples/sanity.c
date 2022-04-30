#include <stdio.h>

int fuzz(char *buffer, size_t size)
{
    return 0;
}

int main(int argc, char *argv[])
{
    fuzz(argv[1], 10);
    return 0;
}
