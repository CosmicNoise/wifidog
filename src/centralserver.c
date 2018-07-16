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
/** @file centralserver.c
  @brief Functions to talk to the central server (auth/send stats/get rules/etc...)
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>


//#include "httpd.h"

#include "common.h"
#include "safe.h"
#include "util.h"
#include "auth.h"
#include "conf.h"
#include "debug.h"
#include "centralserver.h"
#include "fw.h"
#include "../config.h"

//#include <json-c/json.h>
//#include <dlfcn.h>

extern pthread_mutex_t	config_mutex;

/** Initiates a transaction with the auth server, either to authenticate or to
 * update the traffic counters at the server
@param authresponse Returns the information given by the central server 
@param request_type Use the REQUEST_TYPE_* defines in centralserver.h
@param ip IP adress of the client this request is related to
@param mac MAC adress of the client this request is related to
@param token Authentification token of the client
@param incoming Current counter of the client's total incoming traffic, in bytes 
@param outgoing Current counter of the client's total outgoing traffic, in bytes 
*/

t_authcode
auth_server_request(const char *ip, const char *mac)
{
	int sockfd;
	char buf[MAX_BUF];
	char content[MAX_BUF];
	char *tmp;
	ssize_t	numbytes = 0; 
	size_t totalbytes = 0; 
	int done, nfds;
	int ret = 0;
	void *json;
	fd_set			readfds;
	struct timeval		timeout;
	t_auth_serv	*auth_server = NULL;
	auth_server = get_auth_server();
	debug(LOG_ERR, "authserv_hostname:%s", auth_server->authserv_hostname);
	sockfd = connect_auth_server();
	if (sockfd == -1) {
		/* Could not connect to any auth server */
		return (AUTH_ERROR);
	}

	/**
	 * TODO: XXX change the PHP so we can harmonize stage as request_type
	 * everywhere.
	 */
	snprintf(content, (sizeof(content) - 1),
		"{\"OPType\":\"get\", \"Parameter\":{ \"routermac\":\"%s\", \"mac\":\"%s\"}}\0", get_iface_mac(config_get_config()->external_interface), mac);
	snprintf(buf, (sizeof(buf) - 1),
		"POST %s%s HTTP/1.0\r\n"
		"User-Agent: WiFiDog %s\r\n"
		"Host: %s\r\n"		
		"Content-Length: %d\r\n"
		"Content-Type: application/json;charset:utf-8\r\n"
		"\r\n"
		"%s"
		"\r\n",
		auth_server->authserv_path,
		auth_server->authserv_auth_script_path_fragment,
		VERSION,
		auth_server->authserv_hostname,
		strlen(content),
		content
	);


	debug(LOG_ERR, "Sending HTTP request to auth server: [%s]\n", buf);
	send(sockfd, buf, strlen(buf), 0);
	bzero(buf, MAX_BUF);
	debug(LOG_ERR, "Reading response");
	done = 0;
	do {
		FD_ZERO(&readfds);
		FD_SET(sockfd, &readfds);
		timeout.tv_sec = 30; /* XXX magic... 30 second is as good a timeout as any */
		timeout.tv_usec = 0;
		nfds = sockfd + 1;

		nfds = select(nfds, &readfds, NULL, NULL, &timeout);

		if (nfds > 0) {
			/** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
			numbytes = read(sockfd, buf + totalbytes, MAX_BUF - (totalbytes + 1));
			if (numbytes < 0) {
				debug(LOG_ERR, "An error occurred while reading from auth server: %s", strerror(errno));
				/* FIXME */
				close(sockfd);
				return (AUTH_ERROR);
			}
			else if (numbytes == 0) {
				done = 1;
			}
			else {
				totalbytes += numbytes;
				debug(LOG_DEBUG, "Read %d bytes, total now %d", numbytes, totalbytes);
			}
		}
		else if (nfds == 0) {
			debug(LOG_ERR, "Timed out reading data via select() from auth server");
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
		else if (nfds < 0) {
			debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
			/* FIXME */
			close(sockfd);
			return (AUTH_ERROR);
		}
	} while (!done);

	close(sockfd);

	buf[totalbytes] = '\0';
	debug(LOG_DEBUG, "HTTP Response from Server: [%s]", buf);

	#if 0
	json = dlopen("/usr/lib/libjson-c.so", RTLD_LAZY); 
	if (json) {
		struct json_object *(*parse)(char *);
		struct json_object *result;
		char *(*json_get_string)(struct json_object*);
		parse = dlsym(json, "json_tokener_parse");
		if (parse) {
			result = parse(buf);
			json_get_string = dlsym(json, "json_object_get_string");
			if (result && json_get_string){
				debug(LOG_INFO, "%s\n", json_get_string(result));
				json_object_put(result);
			}
		}
		dlclose(json);
	}
	else {
		debug(LOG_INFO, "open json library error\n");
	}
	#endif
	if ((tmp = strstr(buf, "success")) && strstr(buf, mac)) {
	/*
		if (sscanf(tmp, "ret:\"%s", (int *)&ret) == 1) {
			debug(LOG_INFO, "Auth server returned authentication code %d", ret);
			return ret;
		} else {
			debug(LOG_WARNING, "Auth server did not return expected authentication code");
			return(AUTH_ERROR);
		}
		*/
		return (AUTH_ALLOWED);
	}
	else if((tmp = strstr(buf, "error"))) {
		return (AUTH_DENIED);
	}
	
	/* XXX Never reached because of the above if()/else pair. */
	return(AUTH_ERROR);
}

/* Tries really hard to connect to an auth server. Returns a file descriptor, -1 on error
 */
int connect_auth_server() {
	int sockfd;

	LOCK_CONFIG();
	sockfd = _connect_auth_server(0);
	UNLOCK_CONFIG();

	if (sockfd == -1) {
		debug(LOG_ERR, "Failed to connect to any of the auth servers");
		mark_auth_offline();
	}
	else {
		debug(LOG_DEBUG, "Connected to auth server");
		mark_auth_online();
	}
	return (sockfd);
}

/* Helper function called by connect_auth_server() to do the actual work including recursion
 * DO NOT CALL DIRECTLY
 @param level recursion level indicator must be 0 when not called by _connect_auth_server()
 */
int _connect_auth_server(int level) {
	s_config *config = config_get_config();
	t_auth_serv *auth_server = NULL;
	struct in_addr *h_addr;
	int num_servers = 0;
	char * hostname = NULL;
	char * popular_servers[] = {
		  "www.baidu.com",
		  "www.126.com",
		  NULL
	};
	char ** popularserver;
	char * ip;
	struct sockaddr_in their_addr;
	int sockfd;

	/* XXX level starts out at 0 and gets incremented by every iterations. */
	level++;

	/*
	 * Let's calculate the number of servers we have
	 */
	for (auth_server = config->auth_servers; auth_server; auth_server = auth_server->next) {
		num_servers++;
	}
	debug(LOG_DEBUG, "Level %d: Calculated %d auth servers in list", level, num_servers);

	if (level > num_servers) {
		/*
		 * We've called ourselves too many times
		 * This means we've cycled through all the servers in the server list
		 * at least once and none are accessible
		 */
		return (-1);
	}

	/*
	 * Let's resolve the hostname of the top server to an IP address
	 */
	auth_server = config->auth_servers;
	hostname = auth_server->authserv_hostname;
	debug(LOG_DEBUG, "Level %d: Resolving auth server [%s]", level, hostname);
	h_addr = wd_gethostbyname(hostname);
	if (!h_addr) {
		/*
		 * DNS resolving it failed
		 *
		 * Can we resolve any of the popular servers ?
		 */
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] failed", level, hostname);
		mark_offline();
		debug(LOG_DEBUG, "Level %d: Failed to resolve auth server and all popular servers. "
					"The internet connection is probably down", level);
		return(-1);
	}
	else {
		/*
		 * DNS resolving was successful
		 */
		ip = safe_strdup(inet_ntoa(*h_addr));
		debug(LOG_DEBUG, "Level %d: Resolving auth server [%s] succeeded = [%s]", level, hostname, ip);

		if (!auth_server->last_ip || strcmp(auth_server->last_ip, ip) != 0) {
			/*
			 * But the IP address is different from the last one we knew
			 * Update it
			 */
			debug(LOG_DEBUG, "Level %d: Updating last_ip IP of server [%s] to [%s]", level, hostname, ip);
			if (auth_server->last_ip) free(auth_server->last_ip);
			auth_server->last_ip = ip;

			/* Update firewall rules */
			//fw_clear_authservers();
			//fw_set_authservers();
		}
		else {
			/*
			 * IP is the same as last time
			 */
			free(ip);
		}

		/*
		 * Connect to it
		 */
		debug(LOG_DEBUG, "Level %d: Connecting to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
		their_addr.sin_family = AF_INET;
		their_addr.sin_port = htons(auth_server->authserv_http_port);
		their_addr.sin_addr = *h_addr;
		memset(&(their_addr.sin_zero), '\0', sizeof(their_addr.sin_zero));
		free (h_addr);

		if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			debug(LOG_ERR, "Level %d: Failed to create a new SOCK_STREAM socket: %s", strerror(errno));
			return(-1);
		}

		if (connect(sockfd, (struct sockaddr *)&their_addr, sizeof(struct sockaddr)) == -1) {
			/*
			 * Failed to connect
			 * Mark the server as bad and try the next one
			 */
			debug(LOG_DEBUG, "Level %d: Failed to connect to auth server %s:%d (%s). Marking it as bad and trying next if possible", level, hostname, auth_server->authserv_http_port, strerror(errno));
			close(sockfd);
			mark_auth_server_bad(auth_server);
			return _connect_auth_server(level); /* Yay recursion! */
		}
		else {
			/*
			 * We have successfully connected
			 */
			debug(LOG_DEBUG, "Level %d: Successfully connected to auth server %s:%d", level, hostname, auth_server->authserv_http_port);
			return sockfd;
		}
	}
}
