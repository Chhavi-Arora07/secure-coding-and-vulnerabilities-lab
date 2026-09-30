/* module_fixed.c - remediated version of module.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

/* ---- Fix 1 & 2: checked allocation with overflow-safe size calculation ---- */
int *alloc_records(int count, size_t *out_len)
{
    *out_len = 0;

    if (count <= 0)
        return NULL;                            /* reject non-positive counts */

    if ((size_t)count > SIZE_MAX / sizeof(int)) /* would count*sizeof(int) overflow? */
        return NULL;

    size_t n = (size_t)count;
    int *arr = malloc(n * sizeof(int));
    if (arr == NULL)                            /* malloc return value checked */
        return NULL;

    for (size_t i = 0; i < n; i++)
        arr[i] = (int)i;

    *out_len = n;
    return arr;
}

/* ---- Fix 3: no use-after-free (pointer cleared, no use after clearing) ---- */
void uaf_demo(void)
{
    char *msg = malloc(32);
    if (msg == NULL)
        return;

    /* snprintf bounds the copy and always NUL-terminates */
    if (snprintf(msg, 32, "%s", "session-token") >= 32) {
        free(msg);
        msg = NULL;
        return;
    }

    printf("token = %s\n", msg);                /* used only while still valid */

    free(msg);
    msg = NULL;                                 /* no dangling pointer left behind */
}

/* ---- Fix 4: single, correct free ---- */
void double_free_demo(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return;

    *p = 7;
    free(p);
    p = NULL;                                   /* freed exactly once */
}

/* ---- Fix 5: variable always initialised ---- */
int uninit_demo(int flag)
{
    int total = 0;                              /* deterministic default */

    if (flag)
        total = 100;

    return total;
}

/* ---- Fix 6: safe multiplication with range checking ---- */
bool scale(int quantity, int unit_price, int *result)
{
    if (quantity == 0 || unit_price == 0) {
        *result = 0;
        return true;
    }

    /* detect overflow before it happens, without invoking undefined behaviour */
    if (quantity > INT_MAX / unit_price || quantity < INT_MIN / unit_price) {
        return false;                           /* would overflow: reject */
    }

    *result = quantity * unit_price;
    return true;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s alloc|uaf|dfree|uninit|overflow\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "alloc") == 0) {
        size_t len = 0;
        int count = (argc > 2) ? atoi(argv[2]) : 700000000;
        int *a = alloc_records(count, &len);
        if (a == NULL) {
            fprintf(stderr, "alloc_records: allocation rejected or failed\n");
            return EXIT_FAILURE;
        }
        printf("a[0]=%d (len=%zu)\n", a[0], len);
        free(a);
    } else if (strcmp(argv[1], "uaf") == 0) {
        uaf_demo();
    } else if (strcmp(argv[1], "dfree") == 0) {
        double_free_demo();
    } else if (strcmp(argv[1], "uninit") == 0) {
        printf("total = %d\n", uninit_demo(0));
    } else if (strcmp(argv[1], "overflow") == 0) {
        int result = 0;
        if (!scale(2000000000, 5, &result)) {
            fprintf(stderr, "scale: result would overflow, rejected\n");
            return EXIT_FAILURE;
        }
        printf("result = %d\n", result);
    }

    return EXIT_SUCCESS;
}
