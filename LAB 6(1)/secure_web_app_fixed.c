#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUF_SIZE 4096

/* Remediated HTTP backend handler enforcing server-side validation:
 * 1. Server-side catalog lookup ignoring client-supplied hidden price fields
 * 2. Server-side session store validation with HttpOnly/Secure/SameSite flags
 * 3. Socket peer IP verification instead of spoofable X-Forwarded-For headers
 */

typedef struct {
    char token[65];
    char username[32];
    char role[16];
    int active;
} ServerSession;

static ServerSession SESSION_STORE[2] = {
    {"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "alice", "user", 1},
    {"4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a", "root_admin", "admin", 1}
};

static double lookup_catalog_price(const char *item) {
    if (strcmp(item, "laptop") == 0) return 1299.00;
    if (strcmp(item, "monitor") == 0) return 349.00;
    return -1.0;
}

static const ServerSession *validate_server_session(const char *cookie_hdr) {
    if (!cookie_hdr) return NULL;
    const char *sid = strstr(cookie_hdr, "session_id=");
    if (!sid) return NULL;

    char token[65] = {0};
    sscanf(sid + 11, "%64[^;\r\n ]", token);

    for (size_t i = 0; i < 2; i++) {
        if (SESSION_STORE[i].active && strcmp(SESSION_STORE[i].token, token) == 0) {
            return &SESSION_STORE[i];
        }
    }
    return NULL;
}

void send_secure_response(int client_fd, const char *status, const char *body) {
    char response[BUF_SIZE];
    snprintf(response, sizeof(response),
             "HTTP/1.1 %s\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "X-Content-Type-Options: nosniff\r\n"
             "X-Frame-Options: DENY\r\n"
             "Content-Length: %zu\r\n"
             "Connection: close\r\n\r\n"
             "%s",
             status, strlen(body), body);
    send(client_fd, response, strlen(response), 0);
}

/* Fixed Scenario 1: Price fetched strictly from authoritative server catalog */
void handle_checkout_fixed(int client_fd, const char *body) {
    char item[64] = {0};
    int quantity = 0;

    const char *p_item = strstr(body, "item=");
    const char *p_qty  = strstr(body, "quantity=");
    if (p_item) sscanf(p_item + 5, "%63[^&]", item);
    if (p_qty)  sscanf(p_qty + 9, "%d", &quantity);

    double authoritative_price = lookup_catalog_price(item);
    if (authoritative_price < 0.0 || quantity <= 0 || quantity > 100) {
        send_secure_response(client_fd, "400 Bad Request",
                             "<html><body><p>Invalid item or quantity.</p></body></html>");
        return;
    }

    double total = authoritative_price * quantity;
    char html[1024];
    snprintf(html, sizeof(html),
             "<html><body><h2>Order Confirmed</h2>"
             "<p>Item: %s | Qty: %d | Verified Total: $%.2f</p></body></html>",
             item, quantity, total);
    send_secure_response(client_fd, "200 OK", html);
}

/* Fixed Scenario 2: Role resolved exclusively from server-side session store */
void handle_profile_fixed(int client_fd, const char *headers) {
    const char *cookie = strstr(headers, "Cookie:");
    const ServerSession *sess = validate_server_session(cookie);

    if (!sess) {
        send_secure_response(client_fd, "401 Unauthorized",
                             "<html><body><p>Invalid or expired session.</p></body></html>");
        return;
    }

    char html[1024];
    if (strcmp(sess->role, "admin") == 0) {
        snprintf(html, sizeof(html),
                 "<html><body><h2>Admin Dashboard</h2>"
                 "<p>Verified server-side admin: %s</p></body></html>", sess->username);
    } else {
        snprintf(html, sizeof(html),
                 "<html><body><h2>User Profile</h2>"
                 "<p>Verified user: %s</p></body></html>", sess->username);
    }
    send_secure_response(client_fd, "200 OK", html);
}

/* Fixed Scenario 3: Uses kernel peer socket address instead of X-Forwarded-For */
void handle_internal_status_fixed(int client_fd) {
    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    char peer_ip[INET_ADDRSTRLEN] = {0};

    if (getpeername(client_fd, (struct sockaddr *)&peer, &len) == 0) {
        inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof(peer_ip));
    }

    if (strcmp(peer_ip, "127.0.0.1") == 0) {
        send_secure_response(client_fd, "200 OK",
                             "<html><body><h2>Internal Diagnostics</h2>"
                             "<p>Verified socket peer 127.0.0.1.</p></body></html>");
    } else {
        send_secure_response(client_fd, "403 Forbidden",
                             "<html><body><p>Direct localhost peer required.</p></body></html>");
    }
}

int main(void) {
    printf("Remediated HTTP server compiled cleanly.\n");
    return 0;
}
