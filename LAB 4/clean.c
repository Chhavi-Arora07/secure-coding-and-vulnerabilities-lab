#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define NAME_SIZE        16U
#define BUF_SIZE         32U
#define DATA_SIZE        64U
#define LONG_NAME_LEN    8U
#define MODE_PREMIUM     2
#define SECONDS_PER_HOUR 3600
#define SECONDS_PER_DAY  86400
#define USERS_FILE       "users.txt"
/* Returns 0 on success and stores the value in *result; -1 on error. */
static int process(int mode, int *result){
    char name[NAME_SIZE];
    char buf[BUF_SIZE];
    char *data = NULL;
    FILE *fp = NULL;
    int status = -1;
    *result = 0;
    printf("Enter name: ");
    if (fgets(name, (int)sizeof(name), stdin) == NULL) {
        return -1;
    }
    name[strcspn(name, "\n")] = '\0';
    if (snprintf(buf, sizeof(buf), "%s_user", name) >= (int)sizeof(buf)) {
        return -1;
    }
    data = malloc(DATA_SIZE);
    if (data == NULL) {
        return -1;
    }
    fp = fopen(USERS_FILE, "r");
    if (fp == NULL) {
        free(data);
        return -1;
    }
    if (fscanf(fp, "%63s", data) == 1) {
        status = 0;
    }
    if ((status == 0) && (mode == MODE_PREMIUM) && (strlen(name) > LONG_NAME_LEN)) {
        *result = (mode * SECONDS_PER_HOUR) + SECONDS_PER_DAY;
    }
    (void)fclose(fp);
    free(data);
    return status;
}
int main(void){
    int r = 0;
    if (process(MODE_PREMIUM, &r) != 0) {
        (void)fprintf(stderr, "process() failed\n");
        return EXIT_FAILURE;
    }
    printf("Result: %d\n", r);
    return EXIT_SUCCESS;
}