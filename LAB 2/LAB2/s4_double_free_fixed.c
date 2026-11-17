#include <stdio.h>
#include <stdlib.h>

static void cleanup(int **p)              /* takes the address so it can clear the caller's pointer */
{
    free(*p);
    *p = NULL;
}

int main(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return EXIT_FAILURE;

    *p = 7;
    printf("*p = %d\n", *p);

    cleanup(&p);                          /* freed exactly once, p now NULL */
    return EXIT_SUCCESS;
}
