#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *session = malloc(32);
    if (session == NULL)
        return EXIT_FAILURE;

    strcpy(session, "token-abc123");
    printf("session = %s\n", session);    /* use while still valid */

    free(session);
    session = NULL;                       /* no dangling pointer */

    if (session != NULL)                  /* any later use is guarded */
        printf("session = %s\n", session);

    return EXIT_SUCCESS;
}
