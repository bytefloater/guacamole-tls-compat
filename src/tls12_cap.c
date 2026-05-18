#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <openssl/ssl.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define CONF_PATH "/etc/guacamole/tls-compat-hosts.conf"
#define MAX_ENTRIES 256

#define SIGALGS_COMPAT \
    "RSA+SHA1:RSA+SHA256:RSA+SHA384:RSA+SHA512:" \
    "ECDSA+SHA1:ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:" \
    "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512"

typedef struct { uint32_t net; uint32_t mask; } cidr4_t;
typedef struct { uint8_t net[16]; uint8_t mask[16]; } cidr6_t;

static cidr4_t entries4[MAX_ENTRIES];
static int     n4;
static cidr6_t entries6[MAX_ENTRIES];
static int     n6;
static int     debug_mode;

static uint32_t prefix_mask4(int prefix)
{
    return prefix == 0 ? 0 : htonl(~0u << (32 - prefix));
}

static void prefix_mask6(int prefix, uint8_t *mask)
{
    for (int i = 0; i < 16; i++) {
        int bits = prefix - i * 8;
        if (bits >= 8)      mask[i] = 0xff;
        else if (bits <= 0) mask[i] = 0x00;
        else                mask[i] = (uint8_t)(0xff << (8 - bits));
    }
}

static void parse_entry(char *line)
{
    int len = (int)strlen(line);
    while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r' || line[len-1] == ' '))
        line[--len] = '\0';

    if (!len || line[0] == '#') return;

    char *slash = strchr(line, '/');
    int prefix = -1;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    struct in_addr  a4;
    struct in6_addr a6;

    if (inet_pton(AF_INET, line, &a4) == 1) {
        if (n4 >= MAX_ENTRIES) return;
        int p = (prefix < 0 || prefix > 32) ? 32 : prefix;
        entries4[n4].mask = prefix_mask4(p);
        entries4[n4].net  = a4.s_addr & entries4[n4].mask;
        n4++;
    } else if (inet_pton(AF_INET6, line, &a6) == 1) {
        if (n6 >= MAX_ENTRIES) return;
        int p = (prefix < 0 || prefix > 128) ? 128 : prefix;
        prefix_mask6(p, entries6[n6].mask);
        for (int i = 0; i < 16; i++)
            entries6[n6].net[i] = a6.s6_addr[i] & entries6[n6].mask[i];
        n6++;
    }
}

__attribute__((constructor))
static void load_config(void)
{
    debug_mode = getenv("TLSCOMPAT_DEBUG") != NULL;

    FILE *f = fopen(CONF_PATH, "r");
    if (!f) {
        if (debug_mode)
            syslog(LOG_DEBUG, "tls12_cap: config not found: %s", CONF_PATH);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f))
        parse_entry(line);
    fclose(f);

    if (debug_mode)
        syslog(LOG_DEBUG, "tls12_cap: loaded %d IPv4 and %d IPv6 entries from %s",
               n4, n6, CONF_PATH);
}

static int peer_ip_is_targeted(int fd, char *addrstr, size_t addrlen)
{
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);

    if (addrstr && addrlen) addrstr[0] = '\0';

    if (getpeername(fd, (struct sockaddr *)&ss, &len) != 0) {
        if (addrstr) snprintf(addrstr, addrlen, "<getpeername failed>");
        return 0;
    }

    if (ss.ss_family == AF_INET) {
        uint32_t addr = ((struct sockaddr_in *)&ss)->sin_addr.s_addr;
        if (addrstr) inet_ntop(AF_INET, &addr, addrstr, (socklen_t)addrlen);
        for (int i = 0; i < n4; i++)
            if ((addr & entries4[i].mask) == entries4[i].net) return 1;

    } else if (ss.ss_family == AF_INET6) {
        uint8_t *addr = ((struct sockaddr_in6 *)&ss)->sin6_addr.s6_addr;
        if (addrstr) inet_ntop(AF_INET6, addr, addrstr, (socklen_t)addrlen);
        for (int i = 0; i < n6; i++) {
            int match = 1;
            for (int j = 0; j < 16; j++)
                if ((addr[j] & entries6[i].mask[j]) != entries6[i].net[j]) { match = 0; break; }
            if (match) return 1;
        }
    }
    return 0;
}

static void apply_if_targeted(SSL *ssl, int fd)
{
    char addrstr[64];
    int targeted = peer_ip_is_targeted(fd, addrstr, sizeof(addrstr));

    if (debug_mode)
        syslog(LOG_DEBUG, "tls12_cap: fd=%d peer=%s targeted=%d",
               fd, addrstr[0] ? addrstr : "unknown", targeted);

    if (targeted) {
        SSL_set_max_proto_version(ssl, TLS1_2_VERSION);
        SSL_set_security_level(ssl, 0);
        SSL_set1_sigalgs_list(ssl, SIGALGS_COMPAT);

        if (debug_mode)
            syslog(LOG_DEBUG, "tls12_cap: applied legacy TLS downgrade for %s", addrstr);
    }
}

/*
 * FreeRDP 3.x creates a socket BIO with BIO_new_socket() and attaches it via
 * SSL_set_bio() rather than calling SSL_set_fd() directly. SSL_set_bio is
 * called from FreeRDP's own code (external to libssl), so LD_PRELOAD catches
 * it. We extract the fd from the BIO to identify the peer.
 */
void tls12_SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
__asm__(".symver tls12_SSL_set_bio, SSL_set_bio@@OPENSSL_3.0.0");

void tls12_SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio)
{
    typedef void (*fn_t)(SSL *, BIO *, BIO *);
    fn_t real = dlsym(RTLD_NEXT, "SSL_set_bio");
    real(ssl, rbio, wbio);

    int fd = -1;
    if (rbio) BIO_get_fd(rbio, &fd);

    if (debug_mode)
        syslog(LOG_DEBUG, "tls12_cap: SSL_set_bio fd=%d", fd);

    if (fd >= 0)
        apply_if_targeted(ssl, fd);
}

/*
 * Fallback for FreeRDP versions that call SSL_set_fd directly.
 */
int tls12_SSL_set_fd(SSL *ssl, int fd);
__asm__(".symver tls12_SSL_set_fd, SSL_set_fd@@OPENSSL_3.0.0");

int tls12_SSL_set_fd(SSL *ssl, int fd)
{
    typedef int (*fn_t)(SSL *, int);
    fn_t real = dlsym(RTLD_NEXT, "SSL_set_fd");
    int ret = real(ssl, fd);

    if (debug_mode)
        syslog(LOG_DEBUG, "tls12_cap: SSL_set_fd fd=%d", fd);

    if (ret == 1)
        apply_if_targeted(ssl, fd);

    return ret;
}
