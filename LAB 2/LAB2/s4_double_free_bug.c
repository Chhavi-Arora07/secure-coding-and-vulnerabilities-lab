#include <stdio.h>
#include <stdlib.h>

static void cleanup(int *p)
{
    free(p);
}

int main(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return 1;

    *p = 7;
    printf("*p = %d\n", *p);

    cleanup(p);
    free(p);                              /* second free of the same block */
    return 0;
}
