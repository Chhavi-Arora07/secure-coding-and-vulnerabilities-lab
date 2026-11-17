/*
 * lab2.c - Lab 2: Memory Management Error Identification and Remediation
 *
 * All four snippets, original (_bug) and fixed (_fixed), in one file.
 *
 * Build:  gcc -g -fsanitize=address -fno-omit-frame-pointer -o lab2 lab2.c
 * Run:    ASAN_OPTIONS=allocator_may_return_null=1 ./lab2 <1-4> <bug|fixed>
 *
 *   1 = unchecked malloc      2 = unchecked fopen/fgets
 *   3 = use-after-free        4 = double free
 *
 * The *_bug versions are intentionally defective and will crash or be
 * aborted by AddressSanitizer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---------- Snippet 1: unchecked malloc ---------- */
static int s1_bug(void)
{
    size_t n = (size_t)-1 / 2;
    int *data = malloc(n);                /* return value not checked */
    data[0] = 42;                         /* NULL pointer dereference */
    printf("data[0] = %d\n", data[0]);
    free(data);
    return 0;
}

static int s1_fixed(void)
{
    size_t n = (size_t)-1 / 2;
    int *data = malloc(n);
    if (data == NULL) {
        fprintf(stderr, "malloc failed for huge request, using a sane size\n");
        data = malloc(16 * sizeof(int));
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

/* ---------- Snippet 2: unchecked fopen / fgets ---------- */
static int s2_bug(void)
{
    char line[64];
    FILE *fp = fopen("missing_config.txt", "r");   /* not checked */
    fgets(line, sizeof(line), fp);                 /* NULL FILE* */
    printf("first line: %s", line);
    fclose(fp);
    return 0;
}

static int s2_fixed(void)
{
    char line[64];
    FILE *fp = fopen("missing_config.txt", "r");
    if (fp == NULL) {
        fprintf(stderr, "cannot open missing_config.txt\n");
        return EXIT_FAILURE;
    }
    if (fgets(line, sizeof(line), fp) == NULL) {
        fprintf(stderr, "read failed or file empty\n");
        fclose(fp);
        return EXIT_FAILURE;
    }
    printf("first line: %s", line);
    fclose(fp);
    fp = NULL;
    return EXIT_SUCCESS;
}

/* ---------- Snippet 3: use-after-free ---------- */
static int s3_bug(void)
{
    char *session = malloc(32);
    if (session == NULL)
        return 1;
    strcpy(session, "token-abc123");
    free(session);
    printf("session = %s\n", session);    /* use after free */
    return 0;
}

static int s3_fixed(void)
{
    char *session = malloc(32);
    if (session == NULL)
        return EXIT_FAILURE;
    strcpy(session, "token-abc123");
    printf("session = %s\n", session);
    free(session);
    session = NULL;
    if (session != NULL)
        printf("session = %s\n", session);
    return EXIT_SUCCESS;
}

/* ---------- Snippet 4: double free ---------- */
static void s4_cleanup_bug(int *p)
{
    free(p);
}

static int s4_bug(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return 1;
    *p = 7;
    printf("*p = %d\n", *p);
    s4_cleanup_bug(p);
    free(p);                              /* second free */
    return 0;
}

static void s4_cleanup_fixed(int **p)
{
    free(*p);
    *p = NULL;
}

static int s4_fixed(void)
{
    int *p = malloc(sizeof(int));
    if (p == NULL)
        return EXIT_FAILURE;
    *p = 7;
    printf("*p = %d\n", *p);
    s4_cleanup_fixed(&p);
    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <1-4> <bug|fixed>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int n = atoi(argv[1]);
    int fixed = (strcmp(argv[2], "fixed") == 0);

    switch (n) {
    case 1: return fixed ? s1_fixed() : s1_bug();
    case 2: return fixed ? s2_fixed() : s2_bug();
    case 3: return fixed ? s3_fixed() : s3_bug();
    case 4: return fixed ? s4_fixed() : s4_bug();
    default:
        fprintf(stderr, "snippet must be 1-4\n");
        return EXIT_FAILURE;
    }
}
