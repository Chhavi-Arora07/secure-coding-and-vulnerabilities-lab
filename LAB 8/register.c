/*
 * register.c - CLI registration program with NO input validation.
 * Intentionally insecure: for demonstrating abuse cases only.
 */
#include <stdio.h>
#include <string.h>

struct user {
    char name[16];       /* fixed size, never length-checked */
    int  is_admin;       /* sits right after name in memory */
};

int main(void)
{
    struct user u;
    char bio[128];
    int quantity;
    int unit_price = 50;

    u.is_admin = 0;

    printf("Name: ");
    scanf("%s", u.name);                     /* no length limit */

    printf("Bio: ");
    scanf(" ");                              /* skip leftover newline */
    fgets(bio, sizeof(bio), stdin);          /* length-safe, but content not checked */

    printf("Ticket quantity: ");
    scanf("%d", &quantity);                  /* no range check */

    /* Save a profile page; user text is written out exactly as typed. */
    FILE *fp = fopen("profile.html", "w");
    fprintf(fp, "<html><body>\n<h1>Welcome, %s</h1>\n<p>%s</p>\n</body></html>\n", u.name, bio);
    fclose(fp);

    printf("\n--- Registration summary ---\n");
    printf("Name      : %s\n", u.name);
    printf("Role      : %s\n", u.is_admin ? "ADMIN" : "user");
    printf("Quantity  : %d\n", quantity);
    printf("Total due : %d\n", quantity * unit_price);
    printf("Profile page written to profile.html\n");
    return 0;
}
