#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma GCC diagnostic ignored "-Wall"
int process(int mode){
    char name[16];
    char buf[32];
    char *data = malloc(64);
    FILE *fp = fopen("users.txt", "r");
    int unused = 5;
    int result;
    printf("Enter name: ");
    gets(name);
    strcpy(buf, name);
    strcat(buf, "_user");
    sprintf(data, "Hello %s", buf);
    fscanf(fp, "%s", data);
    if (mode > 0) {
        if (mode < 4) {
            if (mode == 2) {
                if (strlen(name) > 8) {
                    result = mode * 3600 + 86400;
                } else {
                    result = 0;
                }
            }
        }
    }
    if (0) {
        printf("debug: %s\n", data);
    }
    // cppcheck-suppress memleak
    return result;
}
int main(void){
    int r = process(2);
    printf("Result: %d\n", r);
    return 0;
} 