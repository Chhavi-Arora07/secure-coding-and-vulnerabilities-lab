#include <stdio.h>

int main(void)
{
    char line[64];
    FILE *fp = fopen("missing_config.txt", "r");   /* return value not checked */

    fgets(line, sizeof(line), fp);                 /* NULL FILE* passed to fgets */
    printf("first line: %s", line);

    fclose(fp);
    return 0;
}
