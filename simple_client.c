#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_IP_LENGTH 16  // Maximum length of IPv4 address string

void handle_error(const char* file, int lineno, const char* msg) {
    fprintf(stderr, "Error in %s at line %d: %s\n", file, lineno, msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

#define HANDLE_ERROR(msg) handle_error(__FILE__, __LINE__, msg)

int main() {
    SSL_CTX* ctx;
    SSL* ssl;
    int sock;
    struct sockaddr_in server_addr;
    char ip_address[MAX_IP_LENGTH];
    int port;

    // Get IP address and port from user
    printf("Enter the IP address to connect to: ");
    if (fgets(ip_address, MAX_IP_LENGTH, stdin) == NULL) {
        fprintf(stderr, "Error reading IP address\n");
        exit(1);
    }
    ip_address[strcspn(ip_address, "\n")] = 0;  // Remove newline if present

    printf("Enter the port number: ");
    if (scanf("%d", &port) != 1) {
        fprintf(stderr, "Error reading port number\n");
        exit(1);
    }

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) HANDLE_ERROR("SSL_CTX_new");

    // Set TLS 1.3 as the minimum version
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) 
        HANDLE_ERROR("SSL_CTX_set_min_proto_version");

     const char *ciphersuites = "TLS_CHACHA20_POLY1305_SHA256";
    if (SSL_CTX_set_ciphersuites(ctx, ciphersuites) != 1) {
        HANDLE_ERROR("SSL_CTX_set_ciphersuites");
    }

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) HANDLE_ERROR("socket");

    // Prepare the server address structure
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_address, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid address/ Address not supported\n");
        exit(1);
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) 
        HANDLE_ERROR("connect");

    // Create a new SSL connection state
    ssl = SSL_new(ctx);
    if (!ssl) HANDLE_ERROR("SSL_new");

    // Set the socket for SSL
    if (!SSL_set_fd(ssl, sock)) HANDLE_ERROR("SSL_set_fd");

    // Perform SSL handshake
    if (SSL_connect(ssl) != 1) HANDLE_ERROR("SSL_connect");

    printf("SSL connection established\n");

    // Send a simple HTTP GET request
    const char* request = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    if (SSL_write(ssl, request, strlen(request)) <= 0) HANDLE_ERROR("SSL_write");

    // Read the response
    char buffer[4096];
    int bytes;
    while ((bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes] = '\0';  // Null-terminate the received data
        printf("%s", buffer);
    }

    if (bytes < 0) HANDLE_ERROR("SSL_read");

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
