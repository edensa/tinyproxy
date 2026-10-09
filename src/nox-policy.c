#include "nox-policy.h"
#include <fnmatch.h>

static int parse_port (const char *s, const char **end, unsigned short *port)
{
        unsigned long n = 0;
        if (*s < '0' || *s > '9') return -1;
        do {
                n = n * 10 + (*s++ - '0');
                if (n > 65535) return -1;
        } while (*s >= '0' && *s <= '9');
        if (!n) return -1;
        *port = n;
        *end = s;
        return 0;
}

static int parse_address (const char *host, unsigned char *addr)
{
        if (inet_pton (AF_INET, host, addr) == 1) return AF_INET;
        if (inet_pton (AF_INET6, host, addr) == 1) return AF_INET6;
        return 0;
}

static int hostname_valid (const char *host, int pattern)
{
        const unsigned char *p = (const unsigned char *) host;
        size_t len = strlen (host), i;
        int label = 0;
        if (!len || len > 253) return 0;
        if (p[len - 1] == '.') --len;
        if (!len) return 0;
        for (i = 0; i < len; ++i) {
                if (p[i] == '.') {
                        if (!label) return 0;
                        label = 0;
                } else if ((p[i] >= 'a' && p[i] <= 'z') ||
                           (p[i] >= 'A' && p[i] <= 'Z') ||
                           (p[i] >= '0' && p[i] <= '9') ||
                           p[i] == '-' || p[i] == '_') {
                        label = 1;
                } else if (pattern && p[i] == '*') {
                        label = 1;
                } else return 0;
        }
        /* A numeric-looking hostname must not turn into an IP via libc's
         * abbreviated/octal/decimal IPv4 address parsing. */
        if (!label) return 0;
        if (!pattern) {
                for (i = 0; i < len; ++i)
                        if ((p[i] < '0' || p[i] > '9') && p[i] != '.') break;
                if (i == len) return 0;
        }
        return 1;
}

static int classify (const char *host, unsigned char *addr)
{
        int family = parse_address (host, addr);
        if (family) return family;

        if (host[0] >= '0' && host[0] <= '9') {
                struct addrinfo hints = {0}, *result;
                hints.ai_family = AF_UNSPEC;
                hints.ai_flags = AI_NUMERICHOST;
                if (getaddrinfo (host, NULL, &hints, &result) == 0) {
                        freeaddrinfo (result);
                        return 0; /* Non-canonical numeric literal. */
                }
        }
        return hostname_valid (host, 0) ? 1 : 0;
}

static int in_prefix (const unsigned char *address, const unsigned char *network,
                      unsigned prefix)
{
        unsigned bytes = prefix / 8, bits = prefix % 8;
        if (memcmp (address, network, bytes)) return 0;
        return !bits || ((address[bytes] ^ network[bytes]) & (0xff << (8 - bits))) == 0;
}

int nox_rule_add (struct nox_rule **rules, const char *host, const char *ports)
{
        struct nox_rule *rule;
        const char *end;
        char *slash, *name;
        size_t len = strlen (host);
        unsigned long prefix = 0;
        unsigned max;
        int family;
        unsigned char address[16];
        unsigned short first, last;

        if (!len || len > 253 || parse_port (ports, &end, &first)) return -1;
        last = first;
        if (*end == '-') {
                if (parse_port (end + 1, &end, &last) || last < first) return -1;
        }
        if (*end) return -1;
        name = strdup (host);
        if (!name) return -1;
        slash = strchr (name, '/');
        if (slash) {
                const char *p = slash + 1;
                *slash = '\0';
                family = parse_address (name, address);
                if (!family || !*p) goto invalid;
                max = family == AF_INET ? 32 : 128;
                while (*p >= '0' && *p <= '9') {
                        prefix = prefix * 10 + (*p++ - '0');
                        if (prefix > max) goto invalid;
                }
                if (*p) goto invalid;
        } else {
                family = parse_address (name, address);
                prefix = family == AF_INET ? 32 : 128;
                if (!family && !hostname_valid (name, 1)) goto invalid;
        }
        rule = calloc (1, sizeof (*rule));
        if (!rule) goto invalid;
        rule->first_port = first;
        rule->last_port = last;
        rule->family = family;
        rule->prefix = prefix;
        if (family) {
                memcpy (rule->address, address, family == AF_INET ? 4 : 16);
                free (name);
        } else {
                if (name[strlen (name) - 1] == '.') name[strlen (name) - 1] = '\0';
                rule->host = name;
                for (slash = name; *slash; ++slash)
                        *slash = tolower ((unsigned char) *slash);
        }
        rule->next = *rules;
        *rules = rule;
        return 0;
invalid:
        free (name);
        return -1;
}

void nox_rules_free (struct nox_rule *rules)
{
        while (rules) {
                struct nox_rule *next = rules->next;
                free (rules->host);
                free (rules);
                rules = next;
        }
}

static int ipv4_mapped (const unsigned char *address)
{
        static const unsigned char prefix[12] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff
        };
        return memcmp (address, prefix, sizeof prefix) == 0;
}

static int cidr_match (const struct nox_rule *rule, int family,
                       const unsigned char *address)
{
        if (rule->family == family && in_prefix (address, rule->address, rule->prefix))
                return 1;
        /* IPv4-mapped IPv6 DNS answers and literals obey IPv4 CIDRs too. */
        if (family == AF_INET6 && rule->family == AF_INET &&
            ipv4_mapped (address))
                return in_prefix (address + 12, rule->address, rule->prefix);
        return 0;
}

static int global_address (int family, const unsigned char *a)
{
        static const struct { unsigned char ip[4], prefix; } reserved[] = {
                {{0,0,0,0},8}, {{10,0,0,0},8}, {{100,64,0,0},10},
                {{127,0,0,0},8}, {{169,254,0,0},16}, {{172,16,0,0},12},
                {{192,0,0,0},24}, {{192,0,2,0},24}, {{192,88,99,0},24},
                {{192,168,0,0},16}, {{198,18,0,0},15},
                {{198,51,100,0},24}, {{203,0,113,0},24},
                {{224,0,0,0},4}, {{240,0,0,0},4}
        };
        size_t i;
        if (family == AF_INET6) {
                if (ipv4_mapped (a))
                        return global_address (AF_INET, a + 12);
                /* Deny non-unicast and non-global special-purpose ranges,
                 * including 6to4 and documentation addresses. */
                return (a[0] & 0xe0) == 0x20 &&
                       !(a[0] == 0x20 && a[1] == 0x01 &&
                         (a[2] < 0x04 || (a[2] == 0x0d && a[3] == 0xb8))) &&
                       !(a[0] == 0x20 && a[1] == 0x02);
        }
        if (family != AF_INET) return 0;
        for (i = 0; i < sizeof reserved / sizeof reserved[0]; ++i)
                if (in_prefix (a, reserved[i].ip, reserved[i].prefix)) return 0;
        return 1;
}

int nox_host_allowed (const struct nox_rule *rules, const char *host, int port)
{
        unsigned char ip[16];
        int family = classify (host, ip);
        size_t len;
        char normalized[254];
        if (!family || port < 1 || port > 65535) return 0;
        if (family != 1) {
                for (; rules; rules = rules->next)
                        if (rules->family && port >= rules->first_port &&
                            port <= rules->last_port && cidr_match (rules, family, ip))
                                return 1;
                return 0;
        }
        len = strlen (host);
        if (host[len - 1] == '.') --len;
        for (size_t i = 0; i < len; ++i)
                normalized[i] = tolower ((unsigned char) host[i]);
        normalized[len] = '\0';
        for (; rules; rules = rules->next)
                if (!rules->family && port >= rules->first_port &&
                    port <= rules->last_port &&
                    fnmatch (rules->host, normalized, 0) == 0) return 1;
        return 0;
}

int nox_address_allowed (const struct nox_rule *rules, const char *host,
                         int port, const struct sockaddr *address)
{
        unsigned char host_ip[16];
        const unsigned char *ip;
        int family = address->sa_family, host_family = classify (host, host_ip);
        if (family == AF_INET)
                ip = (const unsigned char *) &((const struct sockaddr_in *) address)->sin_addr;
        else if (family == AF_INET6) {
                const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *) address;
                if (v6->sin6_scope_id) return 0;
                ip = (const unsigned char *) &v6->sin6_addr;
        } else return 0;
        if (host_family == 1 && global_address (family, ip)) return 1;
        for (; rules; rules = rules->next)
                if (rules->family && port >= rules->first_port &&
                    port <= rules->last_port && cidr_match (rules, family, ip) &&
                    /* A literal must match the chosen address too. */
                    (host_family == 1 ||
                     (host_family == family && !memcmp (host_ip, ip, family == AF_INET ? 4 : 16)) ||
                     (host_family == AF_INET && family == AF_INET6 &&
                      ipv4_mapped (ip) &&
                      !memcmp (host_ip, ip + 12, 4)))) return 1;
        return 0;
}
