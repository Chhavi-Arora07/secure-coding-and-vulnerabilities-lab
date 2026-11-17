#include <stdio.h>
#include <stdlib.h>

int main(void)
{
    char line[64];
    FILE *fp = fopen("missing_config.txt", "r");
    if (fp == NULL) {                              /* return value checked */
        fprintf(stderr, "cannot open missing_config.txt\n");
        return EXIT_FAILURE;
    }

    if (fgets(line, sizeof(line), fp) == NULL) {   /* fgets result checked too */
        fprintf(stderr, "read failed or file empty\n");
        fclose(fp);
        return EXIT_FAILURE;
    }
    printf("first line: %s", line);

    fclose(fp);
    fp = NULL;
    return EXIT_SUCCESS;
}
