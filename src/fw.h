#ifndef _FW_H_
#define _FW_H_

/** Used by iptables_fw_access to select if the client should be granted of denied access */
typedef enum fw_access_t_ {
    FW_ACCESS_ALLOW,
    FW_ACCESS_DENY
} fw_access_t;

/** @brief Initialize the firewall */
int fw_init(void);

int iptable_init(void);

/** @brief Destroy the firewall */
int fw_destroy(void);

/** @brief Allow a user through the firewall*/
int fw_allow(const char *ip, const char *mac, int profile);

/** @brief Deny a client access through the firewall*/
int fw_access(fw_access_t type, const char *ip, const char *mac);

int fw_redirect(fw_access_t type, const char *ip, const char *mac);

void fw_flush_nat(void);

#endif
