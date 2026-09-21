#include <stdio.h>
#include <stdlib.h>
int main(void){
    int *arr = malloc(10 * sizeof(int));   /* 40 bytes */
    if (arr == NULL)
        return 1;
    for (int i = 0; i < 10; i++)
    arr[i] = i * i;
    printf("arr[9] = %d\n", arr[9]);
    free(arr);             /* memory released */ 
    return 0;
}