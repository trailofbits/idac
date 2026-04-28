#include <stdio.h>

static int add(int a, int b) {
    return a + b;
}

int main(void) {
    int v = add(2, 3);
    printf("tiny:%d\n", v);
    return (v == 5) ? 0 : 1;
}
