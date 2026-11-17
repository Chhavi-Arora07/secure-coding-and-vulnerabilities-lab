#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USER 64
#define MAX_PASS 64
#define SESSION_LEN 32

/* Vulnerable authentication & session handler (CWE-798, CWE-120, CWE-209) */
static const char *HARDCODED_ADMIN_SECRET = "Admin@2026!MasterKey";

typedef struct {
    char username[MAX_USER];
    char role[16];
    char token[SESSION_LEN];
} Session;

Session *create_session_vuln(const char *user_input, const char *pass_input) {
    char user_buf[MAX_USER];
    char pass_buf[MAX_PASS];

    /* CWE-120: Unbounded strcpy allows stack buffer overflow */
    strcpy(user_buf, user_input);
    strcpy(pass_buf, pass_input);

    /* CWE-798: Hardcoded administrative credential & plaintext comparison */
    if (strcmp(user_buf, "admin") == 0 && strcmp(pass_buf, HARDCODED_ADMIN_SECRET) == 0) {
        Session *s = (Session *)malloc(sizeof(Session));
        /* CWE-252: Unchecked malloc return value */
        strcpy(s->username, user_buf);
        strcpy(s->role, "ADMIN");
        /* CWE-338: Predictable PRNG token generation */
        snprintf(s->token, SESSION_LEN, "SESS-%d", rand());
        return s;
    }

    /* CWE-209: Verbose error reveals internal query/credential check details */
    fprintf(stderr, "[AUTH_ERR] Failed login for user='%s' against secret='%s'\n",
            user_buf, HARDCODED_ADMIN_SECRET);
    return NULL;
}

int main(void) {
    Session *s = create_session_vuln("admin", "Admin@2026!MasterKey");
    if (s != NULL) {
        printf("Authenticated: %s (Role: %s, Token: %s)\n", s->username, s->role, s->token);
        free(s);
    }
    return 0;
}
