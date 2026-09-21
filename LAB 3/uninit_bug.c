#include <stdio.h> 
int main(void) { 
    int x;                 /* never initialised */ 
    if (x > 10)            /* decision depends on garbage value */ 
    printf("x is greater than 10\n");
    else
    printf("x is not greater than 10\n");
    return 0;
} 