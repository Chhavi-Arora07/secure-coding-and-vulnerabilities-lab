#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    size_t n = (size_t)-1 / 2;            /* absurdly large request: malloc fails */
    int *data = malloc(n);                /* return value not checked */

    data[0] = 42;                         /* NULL pointer dereference */
    printf("data[0] = %d\n", data[0]);

    free(data);
    return 0;
}
