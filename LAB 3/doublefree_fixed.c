#include <stdio.h>
#include <stdlib.h>
int main(void){
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return 1;
    *p = 42;
    printf("*p = %d\n", *p); 
    free(p);               /* freed exactly once */ 
    p = NULL;              /* no dangling pointer left behind */ 
    return 0;
}