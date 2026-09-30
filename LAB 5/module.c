/* module.c - sample module for security audit (contains intentional defects) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- Defect 1 & 2: unchecked malloc + integer overflow in size calc ---- */
int *alloc_records(int count)
{
    int size = count * (int)sizeof(int);   /* size computed in 'int': can overflow */
    int *arr = malloc(size);               /* wrong size passed; return not checked */

    for (int i = 0; i < count; i++)
        arr[i] = i;                        /* NULL deref / heap overflow if size was wrong */

    return arr;
}

/* ---- Defect 3: use-after-free ---- */
void uaf_demo(void)
{
    char *msg = malloc(32);
    if (msg == NULL)
        return;

    strcpy(msg, "session-token");
    free(msg);

    printf("token = %s\n", msg);           /* use after free */
}

/* ---- Defect 4: double free ---- */
void double_free_demo(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return;

    *p = 7;
    free(p);
    free(p);                               /* freed twice */
}

/* ---- Defect 5: uninitialised variable ---- */
int uninit_demo(int flag)
{
    int total;                             /* never given a default */

    if (flag)
        total = 100;

    return total;                          /* garbage when flag == 0 */
}

/* ---- Defect 6: signed integer overflow (undefined behaviour) ---- */
int scale(int quantity, int unit_price)
{
    return quantity * unit_price;          /* wraps/UB for large inputs */
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s alloc|uaf|dfree|uninit|overflow\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "alloc") == 0) {
        int *a = alloc_records(700000000); /* count*4 overflows a 32-bit int */
        printf("a[0]=%d\n", a ? a[0] : -1);
        free(a);
    } else if (strcmp(argv[1], "uaf") == 0) {
        uaf_demo();
    } else if (strcmp(argv[1], "dfree") == 0) {
        double_free_demo();
    } else if (strcmp(argv[1], "uninit") == 0) {
        printf("total = %d\n", uninit_demo(0));
    } else if (strcmp(argv[1], "overflow") == 0) {
        printf("result = %d\n", scale(2000000000, 5));
    }

    return 0;
}
