#include <stdio.h>
#include <stdlib.h>
int main(void){
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return 1;
    *p = 42;
    printf("*p = %d\n", *p);
    free(p);
    free(p);               /* second free of the same pointer */ 
    return 0;

}