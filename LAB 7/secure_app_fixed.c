#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define MAX_USER 64
#define MAX_PASS 64
#define SESSION_LEN 65

typedef struct {
    char username[MAX_USER];
    char role[16];
    char token[SESSION_LEN];
} Session;

/* Safe input sanitization: allow only alphanumeric and underscore */
static int is_valid_identifier(const char *str, size_t max_len) {
    if (str == NULL) return 0;
    size_t len = strnlen(str, max_len);
    if (len == 0 || len >= max_len) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)str[i]) && str[i] != '_') {
            return 0;
        }
    }
    return 1;
}

/* Cryptographically strong token read from /dev/urandom */
static int generate_secure_token(char *buf, size_t buf_len) {
    if (buf == NULL || buf_len < 65) return -1;
    unsigned char raw[32];
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand == NULL) return -1;
    size_t n = fread(raw, 1, sizeof(raw), urand);
    fclose(urand);
    if (n != sizeof(raw)) return -1;

    for (size_t i = 0; i < sizeof(raw); i++) {
        snprintf(buf + (i * 2), 3, "%02x", raw[i]);
    }
    buf[64] = '\0';
    return 0;
}

Session *create_session_fixed(const char *user_input, const char *pass_input) {
    if (!is_valid_identifier(user_input, MAX_USER) || pass_input == NULL) {
        fprintf(stderr, "[AUTH_ERR] Invalid authentication request.\n");
        return NULL;
    }

    /* Load expected secret from environment rather than hardcoded source */
    const char *expected_secret = getenv("APP_ADMIN_SECRET");
    if (expected_secret == NULL || strlen(expected_secret) < 12) {
        fprintf(stderr, "[AUTH_ERR] Server authentication configuration unavailable.\n");
        return NULL;
    }

    /* Constant-time comparison to prevent timing side-channels */
    size_t in_len = strnlen(pass_input, MAX_PASS);
    size_t exp_len = strnlen(expected_secret, MAX_PASS);
    unsigned char diff = (unsigned char)(in_len ^ exp_len);
    size_t cmp_len = in_len < exp_len ? in_len : exp_len;
    for (size_t i = 0; i < cmp_len; i++) {
        diff |= (unsigned char)(pass_input[i] ^ expected_secret[i]);
    }

    if (strcmp(user_input, "admin") == 0 && diff == 0) {
        Session *s = (Session *)calloc(1, sizeof(Session));
        if (s == NULL) {
            fprintf(stderr, "[SYS_ERR] Memory allocation failed.\n");
            return NULL;
        }
        snprintf(s->username, sizeof(s->username), "%s", user_input);
        snprintf(s->role, sizeof(s->role), "%s", "ADMIN");
        if (generate_secure_token(s->token, sizeof(s->token)) != 0) {
            free(s);
            return NULL;
        }
        return s;
    }

    /* Generic error message without leaking secrets or user enumeration */
    fprintf(stderr, "[AUTH_ERR] Authentication failed.\n");
    return NULL;
}

int export_report_fixed(const char *filename, const char *audit_banner) {
    if (!is_valid_identifier(filename, 64) || audit_banner == NULL) {
        return -1;
    }

    char filepath[256];
    int written = snprintf(filepath, sizeof(filepath), "/tmp/%s.txt", filename);
    if (written < 0 || (size_t)written >= sizeof(filepath)) {
        return -1;
    }

    FILE *fp = fopen(filepath, "w");
    if (fp == NULL) {
        return -1;
    }

    /* Fixed format string prevents CWE-134 */
    fprintf(fp, "%s\nReport generated successfully.\n", audit_banner);
    fclose(fp);
    fp = NULL;
    return 0;
}

int main(void) {
    setenv("APP_ADMIN_SECRET", "StrongRuntimeSecret#2026", 1);
    Session *s = create_session_fixed("admin", "StrongRuntimeSecret#2026");
    if (s != NULL) {
        printf("Authenticated safely: %s (Role: %s, Token: %.12s...)\n",
               s->username, s->role, s->token);
        free(s);
        s = NULL;
    }
    return 0;
}
