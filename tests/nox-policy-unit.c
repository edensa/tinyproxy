#include "nox-policy.h"

#define CHECK(expr) do { if (!(expr)) { result = __LINE__; goto done; } } while (0)

static int candidate_allowed (const struct nox_rule *allow,
                              const struct nox_rule *deny, const char *host,
                              int port, const char *ip)
{
        struct sockaddr_in v4 = {0};
        struct sockaddr_in6 v6 = {0};
        if (inet_pton (AF_INET, ip, &v4.sin_addr) == 1) {
                v4.sin_family = AF_INET;
                return nox_address_allowed (allow, deny, host, port,
                                            (const struct sockaddr *) &v4);
        }
        if (inet_pton (AF_INET6, ip, &v6.sin6_addr) == 1) {
                v6.sin6_family = AF_INET6;
                return nox_address_allowed (allow, deny, host, port,
                                            (const struct sockaddr *) &v6);
        }
        return -1;
}

int main (void)
{
        struct nox_rule *allow = NULL, *deny = NULL;
        int result = 0;

        /* The hostname remains allowed, but its pinned DNS answer is denied. */
        CHECK (nox_rule_add (&allow, "*.example.org", "443-444") == 0);
        CHECK (nox_rule_add (&allow, "127.0.0.0/8", "443-444") == 0);
        CHECK (nox_rule_add (&deny, "127.0.0.0/8", "443") == 0);
        CHECK (nox_host_allowed (allow, deny, "api.example.org", 443));
        CHECK (!candidate_allowed (allow, deny, "api.example.org", 443, "127.0.0.1"));
        CHECK (!candidate_allowed (allow, deny, "api.example.org", 443,
                                   "::ffff:127.0.0.1"));
        CHECK (candidate_allowed (allow, deny, "api.example.org", 444, "127.0.0.1"));
        CHECK (!nox_host_allowed (allow, deny, "127.0.0.1", 443));
        CHECK (nox_host_allowed (allow, deny, "127.0.0.1", 444));

        /* Denial of a globally routed answer also overrides hostname allow. */
        CHECK (nox_rule_add (&deny, "8.8.8.0/24", "443") == 0);
        CHECK (!candidate_allowed (allow, deny, "api.example.org", 443, "8.8.8.8"));
        CHECK (candidate_allowed (allow, deny, "api.example.org", 443, "8.8.4.4"));

        /* A hostname deny cannot be bypassed by a broad hostname allow. */
        CHECK (nox_rule_add (&allow, "*", "443") == 0);
        CHECK (nox_rule_add (&deny, "*.EXAMPLE.ORG.", "443") == 0);
        CHECK (!nox_host_allowed (allow, deny, "API.EXAMPLE.ORG.", 443));
        CHECK (nox_host_allowed (allow, deny, "unrelated.example.com", 443));
        CHECK (nox_rule_add (&deny, "*HOST.", "443") == 0);
        CHECK (!nox_host_allowed (allow, deny, "localhost", 443));
        CHECK (!nox_host_allowed (allow, deny, "LOCALHOST.", 443));

        CHECK (nox_rule_add (&deny, "::1/128", "443") == 0);
        CHECK (!candidate_allowed (allow, deny, "api.example.org", 443, "::1"));
        CHECK (nox_rule_add (&deny, "bad?host", "443") == -1);
        CHECK (nox_rule_add (&deny, "127.0.0.0/33", "443") == -1);
        CHECK (nox_rule_add (&deny, "example.org", "443-80") == -1);

done:
        nox_rules_free (allow);
        nox_rules_free (deny);
        return result;
}
