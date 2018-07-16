/** @internal
  @file fw_iptables.c
  @brief Firewall iptables functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#include "safe.h"
#include "conf.h"
#include "fw.h"
#include "debug.h"
#include "util.h"
#include "client_list.h"

extern pthread_mutex_t	client_list_mutex;
extern pthread_mutex_t	config_mutex;
extern pid_t restart_orig_pid;
static int fw_do_command(const char *format, ...);

/** Initialize the firewall rules
*/
int iptable_init(void)
{
	char *addr = config_get_config()->portalsite;
	if (NULL == addr){
		debug(LOG_DEBUG, "portal site is no set");
		return -1;
	}
	fw_do_command("-t filter -N zycfirewall");
	fw_do_command("-t filter -I FORWARD -i br-lan -j zycfirewall");
	fw_do_command("-t filter -A zycfirewall -d %s/32 -j RETURN", addr);
	fw_do_command("-t filter -A zycfirewall -j DROP");
	fw_do_command("-t nat -N zycfirewall");
	fw_do_command("-t nat -I PREROUTING -i br-lan -j zycfirewall");
//	fw_do_command("-t nat -A zycfirewall -d captive.g.aaplimg.com -j RETURN -m comment --comment \"apple portal site\"");
//	fw_do_command("-t nat -A zycfirewall -d captive.apple.com -j RETURN -m comment --comment \"apple portal site\"");

	return 1;
}


/** Initialize the firewall rules
 */
int fw_init(void)
{
    int flags, oneopt = 1, zeroopt = 0;
	int result = 0;
	t_client * client = NULL;

   
    debug(LOG_INFO, "Initializing Firewall");
    result = iptable_init();

	if (restart_orig_pid) {
		debug(LOG_INFO, "Restoring firewall rules for clients inherited from parent");
		LOCK_CLIENT_LIST();
		client = client_get_first_client();
		while (client) {
			fw_access(FW_ACCESS_ALLOW, client->ip, client->mac);
			client = client->next;
		}
		UNLOCK_CLIENT_LIST();
	}

	 return result;
}


/** @internal 
 * */
static int fw_do_command(const char *format, ...)
{
	va_list vlist;
	char *fmt_cmd;
	char *cmd;
	int rc;

	va_start(vlist, format);
	safe_vasprintf(&fmt_cmd, format, vlist);
	va_end(vlist);

	safe_asprintf(&cmd, "iptables %s", fmt_cmd);
	free(fmt_cmd);

	debug(LOG_DEBUG, "Executing command: %s", cmd);

	rc = execute(cmd, 1);

	if (rc!=0) {
		debug(LOG_ERR, "iptables command failed(%d): %s", rc, cmd);	
	}

	free(cmd);

	return rc;
}





/** Remove the firewall rules
 * This is used when we do a clean shutdown of WiFiDog and when it starts to make
 * sure there are no rules left over
 */
int fw_destroy(void)
{

	debug(LOG_DEBUG, "Destroying chains in the FILTER table");
	fw_do_command("-t filter -F zycfirewall");
	fw_do_command("-t filter -D FORWARD -i br-lan -j zycfirewall");
	fw_do_command("-t filter -X zycfirewall");
	fw_do_command("-t nat -F zycfirewall");
	fw_do_command("-t nat -D PREROUTING -i br-lan -j zycfirewall");
	fw_do_command("-t nat -X zycfirewall");
	
	return 1;
}
/** Set if a specific client has access through the firewall */
int fw_access(fw_access_t type, const char *ip, const char *mac)
{
	int rc;


	switch(type) {
		case FW_ACCESS_ALLOW:
			//rc = fw_do_command("-t filter -D zycfirewall -m mac --mac-source %s -j DROP", mac);
			rc = fw_do_command("-t filter -I zycfirewall -m mac --mac-source %s -j RETURN", mac);
			break;
		case FW_ACCESS_DENY:
			rc = fw_do_command("-t filter -D zycfirewall -m mac --mac-source %s -j RETURN", mac);
			//rc |= fw_do_command("-t filter -I zycfirewall -m mac --mac-source %s -j DROP", mac);
			break;
		default:
			rc = -1;
			break;
	}

	return rc;
}

int fw_redirect(fw_access_t type, const char *ip, const char *mac)
{
	char *addr = config_get_config()->portalsite;
	if (NULL == addr){
		debug(LOG_DEBUG, "portal site is no set");
		return -1;
	}
	if (FW_ACCESS_ALLOW == type){
		return fw_do_command("-t nat -A zycfirewall -s %s ! -d %s/32 -p tcp -m multiport --dports 80,443,8080 -j DNAT --to-destination 172.30.22.1", ip, addr);
	}
	else if (FW_ACCESS_DENY == type){
		return fw_do_command("-t nat -D zycfirewall -s %s ! -d %s/32 -p tcp -m multiport --dports 80,443,8080 -j DNAT --to-destination 172.30.22.1", ip, addr);
	}
	else{
		debug(LOG_ERR, "firewall operate code error");
		return -1;
	}
}

void fw_flush_nat(void)
{
	fw_do_command("-t nat -F zycfirewall");
}


