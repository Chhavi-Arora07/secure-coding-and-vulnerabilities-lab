#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUF_SIZE 4096

/* Simulated vulnerable HTTP backend handler demonstrating:
 * 1. Trust in client-supplied hidden form field (price / role)
 * 2. Weak predictable session cookie validation
 * 3. Blind trust in X-Forwarded-For / User-Agent request headers
 */

void send_http_response(int client_fd, const char *status, const char *cookie_hdr, const char *body) {
    char response[BUF_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 %s\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "%s"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             status,
             cookie_hdr ? cookie_hdr : "",
             strlen(body),
             body);
    send(client_fd, response, strlen(response), 0);
}

/* Scenario 1: Checkout endpoint trusting client-submitted hidden price field */
void handle_checkout_vuln(int client_fd, const char *body) {
    char item[64] = "unknown";
    double unit_price = 0.0;
    int quantity = 1;

    /* Parses item=laptop&quantity=1&price=1299.00 directly from POST body */
    const char *p_item = strstr(body, "item=");
    const char *p_qty  = strstr(body, "quantity=");
    const char *p_prc  = strstr(body, "price=");

    if (p_item) sscanf(p_item + 5, "%63[^&]", item);
    if (p_qty)  sscanf(p_qty + 9, "%d", &quantity);
    if (p_prc)  sscanf(p_prc + 6, "%lf", &unit_price);

    double total = unit_price * quantity;
    char html[1024];
    snprintf(html, sizeof(html),
             "<html><body><h2>Order Confirmed</h2>"
             "<p>Item: %s | Qty: %d | Charged Total: $%.2f</p></body></html>",
             item, quantity, total);
    send_http_response(client_fd, "200 OK", NULL, html);
}

/* Scenario 2: Profile endpoint accepting client-modified role/session cookie */
void handle_profile_vuln(int client_fd, const char *headers) {
    const char *cookie = strstr(headers, "Cookie:");
    char html[1024];

    /* CWE-565 / CWE-384: Trusting unverified role attribute inside Cookie */
    if (cookie && strstr(cookie, "role=admin") != NULL) {
        snprintf(html, sizeof(html),
                 "<html><body><h2>Admin Dashboard</h2>"
                 "<p>Privileged administrative panel accessed via Cookie.</p></body></html>");
        send_http_response(client_fd, "200 OK", NULL, html);
    } else if (cookie && strstr(cookie, "session_id=") != NULL) {
        snprintf(html, sizeof(html),
                 "<html><body><h2>User Profile</h2>"
                 "<p>Standard user view.</p></body></html>");
        send_http_response(client_fd, "200 OK", NULL, html);
    } else {
        send_http_response(client_fd, "401 Unauthorized", NULL,
                           "<html><body><p>Missing session cookie.</p></body></html>");
    }
}

/* Scenario 3: Admin diagnostics endpoint trusting X-Forwarded-For header */
void handle_internal_status_vuln(int client_fd, const char *headers) {
    const char *xff = strstr(headers, "X-Forwarded-For:");
    char client_ip[64] = "0.0.0.0";

    if (xff) {
        sscanf(xff + 16, " %63[^\r\n]", client_ip);
    }

    /* CWE-290: Authentication bypass by spoofing X-Forwarded-For */
    if (strcmp(client_ip, "127.0.0.1") == 0) {
        send_http_response(client_fd, "200 OK", NULL,
                           "<html><body><h2>Internal Diagnostics</h2>"
                           "<p>Trusted localhost access granted via X-Forwarded-For.</p></body></html>");
    } else {
        send_http_response(client_fd, "403 Forbidden", NULL,
                           "<html><body><p>Access restricted to 127.0.0.1.</p></body></html>");
    }
}

int main(void) {
    printf("Vulnerable HTTP demo handler compiled cleanly.\n");
    return 0;
}
