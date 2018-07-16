/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file auth.c
    @brief Authentication handling thread
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <syslog.h>

#include "safe.h"
#include "conf.h"
#include "debug.h"
#include "auth.h"
#include "centralserver.h"
#include "fw.h"
#include "client_list.h"
#include "util.h"

/* Defined in clientlist.c */
extern	pthread_mutex_t	client_list_mutex;

/* Defined in util.c */
extern long served_this_session;

void
client_sync_with_authserver(void)
{
    t_authresponse  authresponse;
    char            *ip, *mac;
    t_client        *p1, *p2;
    s_config *config = config_get_config();
	t_authcode ret;
	void *iw;
	char *ipaddr = NULL;
	char *maclist = NULL;
	
	/* initialize iwinfo */
	iw = iw_open(); 

	if(iw_get_entry(iw, config->gw_interface, &maclist)){
		debug(LOG_ERR, "iw get client entry error");
		return ;
	}

	if(!maclist){
		fw_flush_nat();
	}

    LOCK_CLIENT_LIST();

    for (p1 = p2 = client_get_first_client(); NULL != p1; p1 = p2) {
        p2 = p1->next;

        ip = safe_strdup(p1->ip);
        mac = safe_strdup(p1->mac);
		if (!mac && !ip) {
			client_list_delete(p1);
			continue;
		}
	
		if(maclist){
			if (iw_get_mac(maclist, mac) != 0){
				// iptable command				
				//remove client's iptable rules
				fw_access(FW_ACCESS_DENY, NULL, mac);
				if (!strncmp(ip, "0.0.0.0", 7)){
					fw_redirect(FW_ACCESS_DENY, ip, mac);
				}
				client_list_delete(p1);
			}
			else {
				/* Checking authentication on the remote server only if we have an auth server */
				if (config->auth_servers != NULL) {
				   ret = auth_server_request(NULL, mac);
				}
		
				if (AUTH_ALLOWED != ret){
					if (p1 = client_list_find_by_mac(mac)){
						//deny client command
						fw_access(FW_ACCESS_DENY, NULL, mac);
						if (!strncmp(ip, "0.0.0.0", 7)){
							ipaddr = arp_get_ip_from_arp(mac);
							fw_redirect(FW_ACCESS_ALLOW, ipaddr, mac);
							free(ipaddr);
						}
						else {
							fw_redirect(FW_ACCESS_ALLOW, ip, mac);
						}
					
						client_list_delete(p1);
					}
				}
				else {
					p1->last_updated = time(NULL);
				}
			}
		}
		else {
			fw_access(FW_ACCESS_DENY, NULL, mac);
			if (!strncmp(ip, "0.0.0.0", 7)){
				fw_redirect(FW_ACCESS_DENY, ip, mac);
			}
			client_list_delete(p1);
			debug(LOG_ERR, "no client associate\n");
		}

        free(ip);
        free(mac);
    }
	UNLOCK_CLIENT_LIST();
    if (maclist){
		free(maclist);
    }
    if (iw){
		iw_close(iw);
    }
}



/** Launches a thread that periodically checks if any of the connections has timed out
@param arg Must contain a pointer to a string containing the IP adress of the client to check to check
@todo Also pass MAC adress? 
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/  
void
thread_client_timeout_check(const void *arg)
{
	pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t		cond_mutex = PTHREAD_MUTEX_INITIALIZER;
	struct	timespec	timeout;
	
	while (1) {
		/* Sleep for config.checkinterval seconds... */
		timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
		timeout.tv_nsec = 0;

		/* Mutex must be locked for pthread_cond_timedwait... */
		pthread_mutex_lock(&cond_mutex);
		
		/* Thread safe "sleep" */
		pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

		/* No longer needs to be locked */
		pthread_mutex_unlock(&cond_mutex);
	
		debug(LOG_DEBUG, "Running client_sync_with_authserver()");
	
		client_sync_with_authserver();
	}
}


