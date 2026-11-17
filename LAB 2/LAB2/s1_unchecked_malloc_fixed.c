#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    size_t n = (size_t)-1 / 2;            /* absurdly large request: malloc fails */
    int *data = malloc(n);
    if (data == NULL) {                   /* return value checked */
        fprintf(stderr, "malloc failed for huge request, using a sane size\n");

        data = malloc(16 * sizeof(int));  /* fall back to a reasonable allocation */
        if (data == NULL) {
            fprintf(stderr, "malloc failed\n");
            return EXIT_FAILURE;
        }
    }

    data[0] = 42;
    printf("data[0] = %d\n", data[0]);

    free(data);
    data = NULL;
    return EXIT_SUCCESS;
}
