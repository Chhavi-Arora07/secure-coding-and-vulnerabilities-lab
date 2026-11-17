#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *session = malloc(32);
    if (session == NULL)
        return 1;

    strcpy(session, "token-abc123");
    free(session);

    printf("session = %s\n", session);    /* use after free */
    return 0;
}
