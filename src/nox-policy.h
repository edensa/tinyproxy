#ifndef TINYPROXY_NOX_POLICY_H
#define TINYPROXY_NOX_POLICY_H

#include "common.h"

struct nox_rule {
        struct nox_rule *next;
        char *host;
        unsigned char address[16];
        unsigned char family;
        unsigned char prefix;
        unsigned short first_port, last_port;
};

/* Returns -1 on invalid input, including invalid glob, CIDR or port. */
int nox_rule_add (struct nox_rule **rules, const char *host, const char *ports);
void nox_rules_free (struct nox_rule *rules);
/* Deny always wins over allow for the requested hostname or literal. */
int nox_host_allowed (const struct nox_rule *allow, const struct nox_rule *deny,
                      const char *host, int port);
/* Checks each pinned DNS candidate; deny CIDRs take precedence over allows. */
int nox_address_allowed (const struct nox_rule *allow, const struct nox_rule *deny,
                         const char *host, int port,
                         const struct sockaddr *address);

#endif
