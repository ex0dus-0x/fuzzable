#include <stdlib.h>

int func(void) {
    func1();
    func2();
    return 0;
}

static int func1() {
    return 0;
}

void func2() {
    return 0;
}