#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>

#include <libubox/uloop.h>

#include "safe.h"
#include "queue.h"
#include "debug.h"
#include "centralserver.h"
#include "fw.h"
#include "client_list.h"
#include "common.h"
#include "util.h"

struct uloop_timeout ghost;

extern	pthread_mutex_t	client_list_mutex;

struct wd_timer_list {
	struct uloop_timeout timer;
	char *ip;
	char *mac;
	int count;
};

static void wd_timer_ghost_cb(struct uloop_timeout *t)
{
	uloop_timeout_set(&ghost, 60000);	
}

void wd_timer_init(void)
{
	memset(&ghost, 0, sizeof(struct uloop_timeout));
	ghost.cb = wd_timer_ghost_cb;
	uloop_timeout_set(&ghost, 60000);
	debug(LOG_DEBUG, "wifidog init worktimer");
}
	
static void wd_timeout_cb(struct uloop_timeout *t)
{
	struct wd_timer_list *w = container_of(t, struct wd_timer_list, timer);
	t_client *client = NULL;
	int ret = 0;
	int is_valid_ip = !!strncmp(w->ip, "0.0.0.0", 7);
	char *ipaddr = NULL;

	if (!is_valid_ip){
		ipaddr = arp_get_ip_from_arp(w->mac);
	}
	else {
		ipaddr = safe_strdup(w->ip);
	}

	ret = auth_server_request(ipaddr, w->mac);
	if (AUTH_ALLOWED == ret){
		LOCK_CLIENT_LIST();
		if ((client = client_list_find_by_mac(w->mac)) == NULL){
			client_list_append(ipaddr, w->mac);
		}
	    UNLOCK_CLIENT_LIST();

		fw_redirect(FW_ACCESS_DENY, ipaddr, w->mac);
		fw_access(FW_ACCESS_ALLOW, NULL, w->mac);

		uloop_timeout_cancel(t);
		free(w->mac);
		free(w->ip);
		free(w);
	}
	else if (AUTH_DENIED == ret){
		LOCK_CLIENT_LIST();
		if ((client = client_list_find_by_mac(w->mac)) != NULL) {
			client_list_delete(client);			
		}
	    UNLOCK_CLIENT_LIST();

		fw_access(FW_ACCESS_DENY, NULL, w->mac);
		fw_redirect(FW_ACCESS_DENY, ipaddr, w->mac);
		fw_redirect(FW_ACCESS_ALLOW, ipaddr, w->mac);

		uloop_timeout_cancel(t);
		free(w->mac);
		free(w->ip);
		free(w);
	}
	else if (w->count > 5){
		uloop_timeout_cancel(t);
		free(w->mac);
		free(w->ip);
		free(w);
	}
	else {
		w->count++;
		uloop_timeout_set(t, 5000);
	}

	if(ipaddr) { free(ipaddr); }
}

void wd_timer_add(const char *ip, const char *mac)
{
	struct wd_timer_list *w;
	w = calloc(1, sizeof(struct wd_timer_list));
	memset(w, 0, sizeof(struct wd_timer_list));
	w->timer.cb = wd_timeout_cb;
	w->ip = safe_strdup(ip);
	w->mac = safe_strdup(mac);
	w->count = 0;
	uloop_timeout_set(&w->timer, 3000);
}

void wd_timer_exit(void)
{
	debug(LOG_DEBUG, "wifidog worktimer exit");
}

