/*
 * listen.c	Handle socket stuff
 *
 * Version:	$Id$
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright 2005,2006  The FreeRADIUS server project
 * Copyright 2005  Alan DeKok <aland@ox.org>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>
#include <freeradius-devel/rad_assert.h>

#ifdef WITH_UDPFROMTO
#include <freeradius-devel/udpfromto.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

/*
 *	Find a per-socket client.
 */
RADCLIENT *client_listener_find(const rad_listen_t *listener,
				const fr_ipaddr_t *ipaddr, int src_port)
{
#ifdef WITH_DYNAMIC_CLIENTS
	int rcode;
	REQUEST *request;
	RADCLIENT *created;
#endif
	time_t now;
	RADCLIENT *client;
	RADCLIENT_LIST *clients;
	listen_socket_t *sock;

	rad_assert(listener != NULL);
	rad_assert(ipaddr != NULL);

	sock = listener->data;
	clients = sock->clients;

	/*
	 *	This HAS to have been initialized previously.
	 */
	rad_assert(clients != NULL);

	client = client_find(clients, ipaddr,sock->proto);
	if (!client) {
		char name[256], buffer[128];
					
#ifdef WITH_DYNAMIC_CLIENTS
	unknown:		/* used only for dynamic clients */
#endif

		/*
		 *	DoS attack quenching, but only in daemon mode.
		 *	If they're running in debug mode, show them
		 *	every packet.
		 */
		if (debug_flag == 0) {
			static time_t last_printed = 0;

			now = time(NULL);
			if (last_printed == now) return NULL;
			
			last_printed = now;
		}

		listener->print(listener, name, sizeof(name));

		radlog(L_ERR, "Ignoring request to %s from unknown client %s port %d"
#ifdef WITH_TCP
		       " proto %s"
#endif
		       , name, inet_ntop(ipaddr->af, &ipaddr->ipaddr,
					 buffer, sizeof(buffer)), src_port
#ifdef WITH_TCP
		       , (sock->proto == IPPROTO_UDP) ? "udp" : "tcp"
#endif
		       );
		return NULL;
	}

#ifndef WITH_DYNAMIC_CLIENTS
	return client;		/* return the found client. */
#else

	/*
	 *	No server defined, and it's not dynamic.  Return it.
	 */
	if (!client->client_server && !client->dynamic) return client;

	now = time(NULL);
	
	/*
	 *	It's a dynamically generated client, check it.
	 */
	if (client->dynamic && (src_port != 0)) {
		/*
		 *	Lives forever.  Return it.
		 */
		if (client->lifetime == 0) return client;
		
		/*
		 *	Rate-limit the deletion of known clients.
		 *	This makes them last a little longer, but
		 *	prevents the server from melting down if (say)
		 *	10k clients all expire at once.
		 */
		if (now == client->last_new_client) return client;

		/*
		 *	It's not dead yet.  Return it.
		 */
		if ((client->created + client->lifetime) > now) return client;
		
		/*
		 *	This really puts them onto a queue for later
		 *	deletion.
		 */
		client_delete(clients, client);

		/*
		 *	Go find the enclosing network again.
		 */
		client = client_find(clients, ipaddr, sock->proto);

		/*
		 *	WTF?
		 */
		if (!client) goto unknown;
		if (!client->client_server) goto unknown;

		/*
		 *	At this point, 'client' is the enclosing
		 *	network that configures where dynamic clients
		 *	can be defined.
		 */
		rad_assert(client->dynamic == 0);
	} else {
		/*
		 *	The IP is unknown, so we've found an enclosing
		 *	network.  Enable DoS protection.  We only
		 *	allow one new client per second.  Known
		 *	clients aren't subject to this restriction.
		 */
		if (now == client->last_new_client) goto unknown;
	}

	client->last_new_client = now;

	request = request_alloc();
	if (!request) goto unknown;

	request->listener = listener;
	request->client = client;
	request->packet = rad_recv(listener->fd, 0x02); /* MSG_PEEK */
	if (!request->packet) {				/* badly formed, etc */
		request_free(&request);
		goto unknown;
	}
	request->reply = rad_alloc_reply(request->packet);
	if (!request->reply) {
		request_free(&request);
		goto unknown;
	}
	request->packet->timestamp = request->timestamp;
	request->number = 0;
	request->priority = listener->type;
	request->server = client->client_server;
	request->root = &mainconfig;

	/*
	 *	Run a fake request through the given virtual server.
	 *	Look for FreeRADIUS-Client-IP-Address
	 *	         FreeRADIUS-Client-Secret
	 *		...
	 *
	 *	and create the RADCLIENT structure from that.
	 */
	DEBUG("server %s {", request->server);

	rcode = module_authorize(0, request);

	DEBUG("} # server %s", request->server);

	if (rcode != RLM_MODULE_OK) {
		request_free(&request);
		goto unknown;
	}

	/*
	 *	If the client was updated by rlm_dynamic_clients,
	 *	don't create the client from attribute-value pairs.
	 */
	if (request->client == client) {
		created = client_create(clients, request);
	} else {
		created = request->client;

		/*
		 *	This frees the client if it isn't valid.
		 */
		if (!client_validate(clients, client, created)) goto unknown;
	}
	request_free(&request);

	if (!created) goto unknown;

	return created;
#endif
}

static int listen_bind(rad_listen_t *this);


int listen_socket_print(rad_listen_t *this, char *buffer, size_t bufsize)
{
	size_t len;
	listen_socket_t *sock = this->data;

#define FORWARD len = strlen(buffer); if (len >= (bufsize + 1)) return 0;buffer += len;bufsize -= len
#define ADDSTRING(_x) strlcpy(buffer, _x, bufsize);FORWARD

	ADDSTRING(this->frs->name);

#ifdef SO_BINDTODEVICE
	if (sock->interface) {
		ADDSTRING(" interface ");
		ADDSTRING(sock->interface);
	}
#endif

#ifdef WITH_TCP
	if (this->recv == auth_tcp_accept) {
		ADDSTRING(" proto tcp");
	}
#endif

#ifdef WITH_TCP
	/*
	 *	TCP sockets get printed a little differently, to make
	 *	it clear what's going on.
	 */
	if (sock->client) {
		ADDSTRING(" from client (");
		ip_ntoh(&sock->other_ipaddr, buffer, bufsize);
		FORWARD;

		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->other_port);
		FORWARD;
		ADDSTRING(") -> (");

		if ((sock->my_ipaddr.af == AF_INET) &&
		    (sock->my_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
			strlcpy(buffer, "*", bufsize);
		} else {
			ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
		}
		FORWARD;
		
		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->my_port);
		FORWARD;

		if (this->server) {
			ADDSTRING(", virtual-server=");
			ADDSTRING(this->server);
		}

		ADDSTRING(")");

		return 1;
	}

	/*
	 *	Maybe it's a socket that we opened to a home server.
	 */
	if ((sock->proto == IPPROTO_TCP) &&
	    (this->type == RAD_LISTEN_PROXY)) {
		ADDSTRING(" (");
		ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
		FORWARD;

		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->my_port);
		FORWARD;
		ADDSTRING(") -> home_server (");

		if ((sock->other_ipaddr.af == AF_INET) &&
		    (sock->other_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
			strlcpy(buffer, "*", bufsize);
		} else {
			ip_ntoh(&sock->other_ipaddr, buffer, bufsize);
		}
		FORWARD;
		
		ADDSTRING(", ");
		snprintf(buffer, bufsize, "%d", sock->other_port);
		FORWARD;

		ADDSTRING(")");

		return 1;
	}
#endif

	ADDSTRING(" address ");
	
	if ((sock->my_ipaddr.af == AF_INET) &&
	    (sock->my_ipaddr.ipaddr.ip4addr.s_addr == htonl(INADDR_ANY))) {
		strlcpy(buffer, "*", bufsize);
	} else {
		ip_ntoh(&sock->my_ipaddr, buffer, bufsize);
	}
	FORWARD;

	ADDSTRING(" port ");
	snprintf(buffer, bufsize, "%d", sock->my_port);
	FORWARD;

	if (this->server) {
		ADDSTRING(" as server ");
		ADDSTRING(this->server);
	}

#undef ADDSTRING
#undef FORWARD

	return 1;
}


/*
 *	Parse an authentication or accounting socket.
 */
int listen_socket_parse(CONF_SECTION *cs, rad_listen_t *this)
{
	int		rcode;
	int		listen_port;
	fr_ipaddr_t	ipaddr;
	listen_socket_t *sock = this->data;
	char		*section_name = NULL;
	CONF_SECTION	*client_cs, *parentcs;

	/*
	 *	Try IPv4 first
	 */
	ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	rcode = cf_item_parse(cs, "ipaddr", PW_TYPE_IPADDR,
			      &ipaddr.ipaddr.ip4addr, NULL);
	if (rcode < 0) return -1;

	if (rcode == 0) { /* successfully parsed IPv4 */
		ipaddr.af = AF_INET;

	} else {	/* maybe IPv6? */
		rcode = cf_item_parse(cs, "ipv6addr", PW_TYPE_IPV6ADDR,
				      &ipaddr.ipaddr.ip6addr, NULL);
		if (rcode < 0) return -1;

		if (rcode == 1) {
			cf_log_err(cf_sectiontoitem(cs),
				   "No address specified in listen section");
			return -1;
		}
		ipaddr.af = AF_INET6;
	}

	rcode = cf_item_parse(cs, "port", PW_TYPE_INTEGER,
			      &listen_port, "0");
	if (rcode < 0) return -1;

	if ((listen_port < 0) || (listen_port > 65535)) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Invalid value for \"port\"");
			return -1;
	}

	sock->proto = IPPROTO_UDP;

	if (cf_pair_find(cs, "proto")) {
#ifndef WITH_TCP
		cf_log_err(cf_sectiontoitem(cs),
			   "System does not support the TCP protocol.  Delete this line from the configuration file.");
		return -1;
#else
		char *proto = NULL;


		rcode = cf_item_parse(cs, "proto", PW_TYPE_STRING_PTR,
				      &proto, "udp");
		if (rcode < 0) return -1;

		if (strcmp(proto, "udp") == 0) {
			sock->proto = IPPROTO_UDP;

		} else if (strcmp(proto, "tcp") == 0) {
			sock->proto = IPPROTO_TCP;

			rcode = cf_item_parse(cs, "max_connections", PW_TYPE_INTEGER,
					      &sock->max_connections, "64");
			if (rcode < 0) return -1;

		} else {
			cf_log_err(cf_sectiontoitem(cs),
				   "Unknown proto name \"%s\"", proto);
			free(proto);
			return -1;
		}
		free(proto);

		/*
		 *	TCP requires a destination IP for sockets.
		 *	UDP doesn't, so it's allowed.
		 */
		if ((this->type == RAD_LISTEN_PROXY) &&
		    (sock->proto != IPPROTO_UDP)) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Proxy listeners can only listen on proto = udp");
			return -1;
		}
#endif
	}

	sock->my_ipaddr = ipaddr;
	sock->my_port = listen_port;

	/*
	 *	If we can bind to interfaces, do so,
	 *	else don't.
	 */
	if (cf_pair_find(cs, "interface")) {
#ifndef SO_BINDTODEVICE
		cf_log_err(cf_sectiontoitem(cs),
			   "System does not support binding to interfaces.  Delete this line from the configuration file.");
		return -1;
#else
		const char *value;
		CONF_PAIR *cp = cf_pair_find(cs, "interface");

		rad_assert(cp != NULL);
		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err(cf_sectiontoitem(cs),
				   "No interface name given");
			return -1;
		}
		sock->interface = value;
#endif
	}

#ifdef WITH_DHCP
	/*
	 *	If we can do broadcasts..
	 */
	if (cf_pair_find(cs, "broadcast")) {
#ifndef SO_BROADCAST
		cf_log_err(cf_sectiontoitem(cs),
			   "System does not support broadcast sockets.  Delete this line from the configuration file.");
		return -1;
#else
		const char *value;
		CONF_PAIR *cp = cf_pair_find(cs, "broadcast");

		if (this->type != RAD_LISTEN_DHCP) {
			cf_log_err(cf_pairtoitem(cp),
				   "Broadcast can only be set for DHCP listeners.  Delete this line from the configuration file.");
			return -1;
		}
		
		rad_assert(cp != NULL);
		value = cf_pair_value(cp);
		if (!value) {
			cf_log_err(cf_sectiontoitem(cs),
				   "No broadcast value given");
			return -1;
		}

		/*
		 *	Hack... whatever happened to cf_section_parse?
		 */
		sock->broadcast = (strcmp(value, "yes") == 0);
#endif
	}
#endif

	/*
	 *	And bind it to the port.
	 */
	if (listen_bind(this) < 0) {
		char buffer[128];
		cf_log_err(cf_sectiontoitem(cs),
			   "Error binding to port for %s port %d",
			   ip_ntoh(&sock->my_ipaddr, buffer, sizeof(buffer)),
			   sock->my_port);
		return -1;
	}

#ifdef WITH_PROXY
	/*
	 *	Proxy sockets don't have clients.
	 */
	if (this->type == RAD_LISTEN_PROXY) return 0;
#endif
	
	/*
	 *	The more specific configurations are preferred to more
	 *	generic ones.
	 */
	client_cs = NULL;
	parentcs = cf_top_section(cs);
	rcode = cf_item_parse(cs, "clients", PW_TYPE_STRING_PTR,
			      &section_name, NULL);
	if (rcode < 0) return -1; /* bad string */
	if (rcode == 0) {
		/*
		 *	Explicit list given: use it.
		 */
		client_cs = cf_section_sub_find_name2(parentcs,
						      "clients",
						      section_name);
		if (!client_cs) {
			client_cs = cf_section_find(section_name);
		}
		if (!client_cs) {
			cf_log_err(cf_sectiontoitem(cs),
				   "Failed to find clients %s {...}",
				   section_name);
			free(section_name);
			return -1;
		}
		free(section_name);
	} /* else there was no "clients = " entry. */

	if (!client_cs) {
		CONF_SECTION *server_cs;

		server_cs = cf_section_sub_find_name2(parentcs,
						      "server",
						      this->server);
		/*
		 *	Found a "server foo" section.  If there are clients
		 *	in it, use them.
		 */
		if (server_cs &&
		    (cf_section_sub_find(server_cs, "client") != NULL)) {
			client_cs = server_cs;
		}
	}

	/*
	 *	Still nothing.  Look for global clients.
	 */
	if (!client_cs) client_cs = parentcs;

	sock->clients = clients_parse_section(client_cs);
	if (!sock->clients) {
		cf_log_err(cf_sectiontoitem(cs),
			   "Failed to load clients for this listen section");
		return -1;
	}

#ifdef WITH_TCP
	if (sock->proto == IPPROTO_TCP) {
		/*
		 *	Re-write the listener receive function to
		 *	allow us to accept the socket.
		 */
		this->recv = auth_tcp_accept;
	}
#endif

	return 0;
}


/*
 *	Binds a listener to a socket.
 */
static int listen_bind(rad_listen_t *this)
{
	int rcode;
	struct sockaddr_storage salocal;
	socklen_t	salen;
	listen_socket_t *sock = this->data;
#ifndef WITH_TCP
#define proto_for_port "udp"
#define sock_type SOCK_DGRAM
#else
	const char *proto_for_port = "udp";
	int sock_type = SOCK_DGRAM;
	
	if (sock->proto == IPPROTO_TCP) {
#ifdef WITH_VMPS
		if (this->type == RAD_LISTEN_VQP) {
			radlog(L_ERR, "VQP does not support TCP transport");
			return -1;
		}
#endif

		proto_for_port = "tcp";
		sock_type = SOCK_STREAM;	
	}
#endif

	/*
	 *	If the port is zero, then it means the appropriate
	 *	thing from /etc/services.
	 */
	if (sock->my_port == 0) {
		struct servent	*svp;

		switch (this->type) {
		case RAD_LISTEN_AUTH:
			svp = getservbyname ("radius", proto_for_port);
			if (svp != NULL) {
				sock->my_port = ntohs(svp->s_port);
			} else {
				sock->my_port = PW_AUTH_UDP_PORT;
			}
			break;

#ifdef WITH_ACCOUNTING
		case RAD_LISTEN_ACCT:
			svp = getservbyname ("radacct", proto_for_port);
			if (svp != NULL) {
				sock->my_port = ntohs(svp->s_port);
			} else {
				sock->my_port = PW_ACCT_UDP_PORT;
			}
			break;
#endif

#ifdef WITH_PROXY
		case RAD_LISTEN_PROXY:
			/* leave it at zero */
			break;
#endif

#ifdef WITH_VMPS
		case RAD_LISTEN_VQP:
			sock->my_port = 1589;
			break;
#endif

#ifdef WITH_COA
		case RAD_LISTEN_COA:
			sock->my_port = PW_COA_UDP_PORT;
			break;
#endif
		default:
			radlog(L_ERR, "ERROR: Non-fatal internal sanity check failed in bind.");
			return -1;
		}
	}

	/*
	 *	Copy fr_socket() here, as we may need to bind to a device.
	 */
	this->fd = socket(sock->my_ipaddr.af, sock_type, 0);
	if (this->fd < 0) {
		radlog(L_ERR, "Failed opening socket: %s", strerror(errno));
		return -1;
	}
		
#ifdef SO_BINDTODEVICE
	/*
	 *	Bind to a device BEFORE touching IP addresses.
	 */
	if (sock->interface) {
		struct ifreq ifreq;
		strcpy(ifreq.ifr_name, sock->interface);

		fr_suid_up();
		rcode = setsockopt(this->fd, SOL_SOCKET, SO_BINDTODEVICE,
				   (char *)&ifreq, sizeof(ifreq));
		fr_suid_down();
		if (rcode < 0) {
			close(this->fd);
			radlog(L_ERR, "Failed binding to interface %s: %s",
			       sock->interface, strerror(errno));
			return -1;
		} /* else it worked. */
	}
#endif

#ifdef WITH_TCP
	if (sock->proto == IPPROTO_TCP) {
		int on = 1;

		if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			close(this->fd);
			radlog(L_ERR, "Failed to reuse address: %s", strerror(errno));
			return -1;
		}
	}
#endif

#if defined(WITH_TCP) && defined(WITH_UDPFROMTO)
	else			/* UDP sockets get UDPfromto */
#endif

#ifdef WITH_UDPFROMTO
	/*
	 *	Initialize udpfromto for all sockets.
	 */
	if (udpfromto_init(this->fd) != 0) {
		close(this->fd);
		return -1;
	}
#endif

	/*
	 *	Set up sockaddr stuff.
	 */
	if (!fr_ipaddr2sockaddr(&sock->my_ipaddr, sock->my_port, &salocal, &salen)) {
		close(this->fd);
		return -1;
	}
		
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	if (sock->my_ipaddr.af == AF_INET6) {
		/*
		 *	Listening on '::' does NOT get you IPv4 to
		 *	IPv6 mapping.  You've got to listen on an IPv4
		 *	address, too.  This makes the rest of the server
		 *	design a little simpler.
		 */
#ifdef IPV6_V6ONLY
		
		if (IN6_IS_ADDR_UNSPECIFIED(&sock->my_ipaddr.ipaddr.ip6addr)) {
			int on = 1;
			
			setsockopt(this->fd, IPPROTO_IPV6, IPV6_V6ONLY,
				   (char *)&on, sizeof(on));
		}
#endif /* IPV6_V6ONLY */
	}
#endif /* HAVE_STRUCT_SOCKADDR_IN6 */

	if (sock->my_ipaddr.af == AF_INET) {
		UNUSED int flag;
		
#if defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_DONT)
		/*
		 *	Disable PMTU discovery.  On Linux, this
		 *	also makes sure that the "don't fragment"
		 *	flag is zero.
		 */
		flag = IP_PMTUDISC_DONT;
		setsockopt(this->fd, IPPROTO_IP, IP_MTU_DISCOVER,
			   &flag, sizeof(flag));
#endif

#if defined(IP_DONTFRAG)
		/*
		 *	Ensure that the "don't fragment" flag is zero.
		 */
		flag = 0;
		setsockopt(this->fd, IPPROTO_IP, IP_DONTFRAG,
			   &flag, sizeof(flag));
#endif
	}

#ifdef WITH_DHCP
#ifdef SO_BROADCAST
	if (sock->broadcast) {
		int on = 1;
		
		if (setsockopt(this->fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) < 0) {
			radlog(L_ERR, "Can't set broadcast option: %s\n",
			       strerror(errno));
			return -1;
		}
	}
#endif
#endif

	/*
	 *	May be binding to priviledged ports.
	 */
	if (sock->my_port != 0) {
#ifdef SO_REUSEADDR
		int on = 1;

		if (setsockopt(this->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			radlog(L_ERR, "Can't set re-use address option: %s\n",
			       strerror(errno));
			return -1;
		}
#endif

		fr_suid_up();
		rcode = bind(this->fd, (struct sockaddr *) &salocal, salen);
		fr_suid_down();
		if (rcode < 0) {
			char buffer[256];
			close(this->fd);
			
			this->print(this, buffer, sizeof(buffer));
			radlog(L_ERR, "Failed binding to %s: %s\n",
			       buffer, strerror(errno));
			return -1;
		}
	
		/*
		 *	FreeBSD jail issues.  We bind to 0.0.0.0, but the
		 *	kernel instead binds us to a 1.2.3.4.  If this
		 *	happens, notice, and remember our real IP.
		 */
		{
			struct sockaddr_storage	src;
			socklen_t	        sizeof_src = sizeof(src);
			
			memset(&src, 0, sizeof_src);
			if (getsockname(this->fd, (struct sockaddr *) &src,
					&sizeof_src) < 0) {
				radlog(L_ERR, "Failed getting socket name: %s",
				       strerror(errno));
				return -1;
			}
			
			if (!fr_sockaddr2ipaddr(&src, sizeof_src,
						&sock->my_ipaddr, &sock->my_port)) {
				radlog(L_ERR, "Socket has unsupported address family");
				return -1;
			}
		}
	}

#ifdef WITH_TCP
	if (sock->proto == IPPROTO_TCP) {
		if (listen(this->fd, 8) < 0) {
			close(this->fd);
			radlog(L_ERR, "Failed in listen(): %s", strerror(errno));
			return -1;
		}
	} else
#endif

	  if (fr_nonblock(this->fd) < 0) {
		  close(this->fd);
		  radlog(L_ERR, "Failed setting non-blocking on socket: %s",
			 strerror(errno));
		  return -1;
	  }

	/*
	 *	Mostly for proxy sockets.
	 */
	sock->other_ipaddr.af = sock->my_ipaddr.af;

/*
 *	Don't screw up other people.
 */
#undef proto_for_port
#undef sock_type

	return 0;
}

#define MAX_HANDLES (32)
static int frs_init = 0;
static lt_dlhandle frs_modules[MAX_HANDLES];


/*
 *	Allocate & initialize a new listener.
 */
rad_listen_t *listen_alloc(const char *type_name)
{
	int i;
	rad_listen_t *this;
	const frs_module_t *frs;
	char buffer[256];

	this = rad_malloc(sizeof(*this));
	memset(this, 0, sizeof(*this));

	snprintf(buffer, sizeof(buffer), "frs_%s", type_name);

	if (!frs_init) {
		memset(frs_modules, 0, sizeof(frs_modules));
		frs_init = TRUE;
	}

	frs = NULL;
	for (i = 0; i < MAX_HANDLES; i++) {
		if (!frs_modules[i]) continue;

		frs = lt_dlsym(frs_modules[i], buffer);
		if (frs) break;
	}
	
	if (!frs) {
		lt_dlhandle handle;

		handle = lt_dlopenext(buffer);
		if (!handle) {
			radlog(L_ERR, "Failed opening %s: %s",
			       buffer, lt_dlerror());
			return NULL;
		}
		
		frs = lt_dlsym(handle, buffer);
		if (!frs) {
			lt_dlclose(handle);
			radlog(L_ERR, "Failed linking to %s: %s",
			       buffer, lt_dlerror());
			return NULL;
		}
	
		if (frs->magic != FRS_MODULE_MAGIC_NUMBER) {
			lt_dlclose(handle);
			radlog(L_ERR, "Invalid version in %s\n",
			       buffer);
			return NULL;
		}

		for (i = 0; i < MAX_HANDLES; i++) {
			if (!frs_modules[i]) {
				frs_modules[i] = handle;
				break;
			}
		} /* if we run out, we leak the handle.  Too bad. */
	}

	this->type = frs->type;
	this->frs = frs;
	this->recv = frs->recv;
	this->send = frs->send;
	this->print = frs->print;
	this->encode = frs->encode;
	this->decode = frs->decode;

	switch (this->type) {
#ifdef WITH_STATS
	case RAD_LISTEN_NONE:
#endif
	case RAD_LISTEN_AUTH:
#ifdef WITH_ACCOUNTING
	case RAD_LISTEN_ACCT:
#endif
#ifdef WITH_PROXY
	case RAD_LISTEN_PROXY:
#endif
#ifdef WITH_VMPS
	case RAD_LISTEN_VQP:
#endif
#ifdef WITH_COA
	case RAD_LISTEN_COA:
#endif
		this->data = rad_malloc(sizeof(listen_socket_t));
		memset(this->data, 0, sizeof(listen_socket_t));
		break;

#ifdef WITH_DHCP
	case RAD_LISTEN_DHCP:
		this->data = rad_malloc(sizeof(dhcp_socket_t));
		memset(this->data, 0, sizeof(dhcp_socket_t));
		break;
#endif

#ifdef WITH_DETAIL
	case RAD_LISTEN_DETAIL:
		this->data = NULL;
		break;
#endif

#ifdef WITH_COMMAND_SOCKET
	/*
	 *	The data here is allocate in the "parse" section.
	 */
	case RAD_LISTEN_COMMAND:
		break;
#endif

	default:
		rad_assert("Unsupported option!" == NULL);
		break;
	}

	return this;
}

#ifdef WITH_PROXY
/*
 *	Externally visible function for creating a new proxy LISTENER.
 *
 *	Not thread-safe, but all calls to it are protected by the
 *	proxy mutex in event.c
 */
int proxy_new_listener(home_server *home, int src_port)
{
	rad_listen_t *this;
	listen_socket_t *sock;

	if (!home) return 0;

	if ((home->max_connections > 0) &&
	    (home->num_connections >= home->max_connections)) {
		DEBUG("WARNING: Home server has too many open connections (%d)",
		      home->max_connections);
		return 0;
	}

	this = listen_alloc(RAD_LISTEN_PROXY);

	sock = this->data;
	sock->other_ipaddr = home->ipaddr;
	sock->other_port = home->port;
	sock->home = home;

	sock->my_ipaddr = home->src_ipaddr;
	sock->my_port = src_port;
	sock->proto = home->proto;

#ifdef WITH_TCP
	sock->last_packet = time(NULL);

	if (home->proto == IPPROTO_TCP) {
		this->recv = proxy_socket_tcp_recv;

		/*
		 *	FIXME: connect() is blocking!
		 *	We do this with the proxy mutex locked, which may
		 *	cause large delays!
		 *
		 *	http://www.developerweb.net/forum/showthread.php?p=13486
		 */
		this->fd = fr_tcp_client_socket(&home->src_ipaddr,
						&home->ipaddr, home->port);
	} else
#endif
		this->fd = fr_socket(&home->src_ipaddr, src_port);

	if (this->fd < 0) {
		DEBUG("Failed opening client socket: %s", fr_strerror());
		listen_free(&this);
		return 0;
	}

	/*
	 *	Figure out which port we were bound to.
	 */
	if (sock->my_port == 0) {
		struct sockaddr_storage	src;
		socklen_t	        sizeof_src = sizeof(src);
		
		memset(&src, 0, sizeof_src);
		if (getsockname(this->fd, (struct sockaddr *) &src,
				&sizeof_src) < 0) {
			radlog(L_ERR, "Failed getting socket name: %s",
			       strerror(errno));
			listen_free(&this);
			return 0;
		}
		
		if (!fr_sockaddr2ipaddr(&src, sizeof_src,
					&sock->my_ipaddr, &sock->my_port)) {
			radlog(L_ERR, "Socket has unsupported address family");
			listen_free(&this);
			return 0;
		}
	}

	/*
	 *	Tell the event loop that we have a new FD
	 */
	event_new_fd(this);
	
	return 1;
}
#endif


static rad_listen_t *listen_parse(CONF_SECTION *cs, const char *server)
{
	int		rcode;
	char		*listen_type;
	rad_listen_t	*this;

	listen_type = NULL;
	
	cf_log_info(cs, "listen {");

	rcode = cf_item_parse(cs, "type", PW_TYPE_STRING_PTR,
			      &listen_type, "");
	if (rcode < 0) return NULL;
	if (rcode == 1) {
		free(listen_type);
		cf_log_err(cf_sectiontoitem(cs),
			   "No type specified in listen section");
		return NULL;
	}

	/*
	 *	Allow listen sections in the default config to
	 *	refer to a server.
	 */
	if (!server) {
		rcode = cf_item_parse(cs, "virtual_server", PW_TYPE_STRING_PTR,
				      &server, NULL);
		if (rcode == 1) { /* compatiblity with 2.0-pre */
			rcode = cf_item_parse(cs, "server", PW_TYPE_STRING_PTR,
					      &server, NULL);
		}
		if (rcode < 0) {
			free(listen_type);
			return NULL;
		}
	}

#ifdef WITH_PROXY
	/*
	 *	We were passed a virtual server, so the caller is
	 *	defining a proxy listener inside of a virtual server.
	 *	This isn't allowed right now.
	 */
	else if (this->type == RAD_LISTEN_PROXY) {
		radlog(L_ERR, "Error: listen type \"proxy\" Cannot appear in a virtual server section");
		return NULL;
	}
#endif

	/*
	 *	Set up cross-type data.
	 */
	this = listen_alloc(listen_type);
	if (!this) return NULL;

	free(listen_type);
	this->server = server;
	this->fd = -1;

	/*
	 *	Call per-type parser.
	 */
	if (this->frs->parse(cs, this) < 0) {
		listen_free(&this);
		return NULL;
	}

	cf_log_info(cs, "}");

	return this;
}

/*
 *	Generate a list of listeners.  Takes an input list of
 *	listeners, too, so we don't close sockets with waiting packets.
 */
int listen_init(CONF_SECTION *config, rad_listen_t **head)
{
	int		override = FALSE;
	int		rcode;
	CONF_SECTION	*cs = NULL;
	rad_listen_t	**last;
	rad_listen_t	*this;
	fr_ipaddr_t	server_ipaddr;
	int		auth_port = 0;
#ifdef WITH_PROXY
	int		defined_proxy = 0;
#endif

	/*
	 *	We shouldn't be called with a pre-existing list.
	 */
	rad_assert(head && (*head == NULL));

	last = head;
	server_ipaddr.af = AF_UNSPEC;

	/*
	 *	If the port is specified on the command-line,
	 *	it over-rides the configuration file.
	 *
	 *	FIXME: If argv[0] == "vmpsd", then don't listen on auth/acct!
	 */
	if (mainconfig.port >= 0) auth_port = mainconfig.port;

	/*
	 *	If the IP address was configured on the command-line,
	 *	use that as the "bind_address"
	 */
	if (mainconfig.myip.af != AF_UNSPEC) {
		memcpy(&server_ipaddr, &mainconfig.myip,
		       sizeof(server_ipaddr));
		override = TRUE;
		goto bind_it;
	}

	/*
	 *	Else look for bind_address and/or listen sections.
	 */
	server_ipaddr.ipaddr.ip4addr.s_addr = htonl(INADDR_NONE);
	rcode = cf_item_parse(config, "bind_address",
			      PW_TYPE_IPADDR,
			      &server_ipaddr.ipaddr.ip4addr, NULL);
	if (rcode < 0) return -1; /* error parsing it */

	if (rcode == 0) { /* successfully parsed IPv4 */
		listen_socket_t *sock;
		server_ipaddr.af = AF_INET;

		radlog(L_INFO, "WARNING: The directive 'bind_adress' is deprecated, and will be removed in future versions of FreeRADIUS. Please edit the configuration files to use the directive 'listen'.");

	bind_it:
#ifdef WITH_VMPS
		if (strcmp(progname, "vmpsd") == 0) {
			this = listen_alloc("vmps");
			if (!this) return 0;	/* FIXME: memleak? */
			if (!auth_port) auth_port = 1589;
		} else
#endif
		{
			this = listen_alloc("auth");
			if (!this) return 0;	/* FIXME: memleak? */
		}

		sock = this->data;

		sock->my_ipaddr = server_ipaddr;
		sock->my_port = auth_port;

		sock->clients = clients_parse_section(config);
		if (!sock->clients) {
			cf_log_err(cf_sectiontoitem(config),
				   "Failed to find any clients for this listen section");
			listen_free(&this);
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(head);
			radlog(L_ERR, "There appears to be another RADIUS server running on the authentication port %d", sock->my_port);
			listen_free(&this);
			return -1;
		}
		auth_port = sock->my_port;	/* may have been updated in listen_bind */
		if (override) {
			cs = cf_section_sub_find_name2(config, "server",
						       mainconfig.name);
			if (cs) this->server = mainconfig.name;
		}

		*last = this;
		last = &(this->next);

#ifdef WITH_VMPS
		/*
		 *	No acct for vmpsd
		 */
		if (strcmp(progname, "vmpsd") == 0) goto add_sockets;
#endif

#ifdef WITH_ACCOUNTING
		/*
		 *	Open Accounting Socket.
		 *
		 *	If we haven't already gotten acct_port from
		 *	/etc/services, then make it auth_port + 1.
		 */
		this = listen_alloc("acct");
		if (!this) return 0;	/* FIXME: memleak? */
		sock = this->data;

		/*
		 *	Create the accounting socket.
		 *
		 *	The accounting port is always the
		 *	authentication port + 1
		 */
		sock->my_ipaddr = server_ipaddr;
		sock->my_port = auth_port + 1;

		sock->clients = clients_parse_section(config);
		if (!sock->clients) {
			cf_log_err(cf_sectiontoitem(config),
				   "Failed to find any clients for this listen section");
			return -1;
		}

		if (listen_bind(this) < 0) {
			listen_free(&this);
			listen_free(head);
			radlog(L_ERR, "There appears to be another RADIUS server running on the accounting port %d", sock->my_port);
			return -1;
		}

		if (override) {
			cs = cf_section_sub_find_name2(config, "server",
						       mainconfig.name);
			if (cs) this->server = mainconfig.name;
		}

		*last = this;
		last = &(this->next);
#endif
	} else if (mainconfig.port > 0) { /* no bind address, but a port */
		radlog(L_ERR, "The command-line says \"-p %d\", but there is no associated IP address to use",
		       mainconfig.port);
		return -1;
	}

	/*
	 *	They specified an IP on the command-line, ignore
	 *	all listen sections except the one in '-n'.
	 */
	if (mainconfig.myip.af != AF_UNSPEC) {
		CONF_SECTION *subcs;
		const char *name2 = cf_section_name2(cs);

		cs = cf_section_sub_find_name2(config, "server",
					       mainconfig.name);
		if (!cs) goto add_sockets;

		/*
		 *	Should really abstract this code...
		 */
		for (subcs = cf_subsection_find_next(cs, NULL, "listen");
		     subcs != NULL;
		     subcs = cf_subsection_find_next(cs, subcs, "listen")) {
			this = listen_parse(subcs, name2);
			if (!this) {
				listen_free(head);
				return -1;
			}

			*last = this;
			last = &(this->next);
		} /* loop over "listen" directives in server <foo> */

		goto add_sockets;
	}

	/*
	 *	Walk through the "listen" sections, if they exist.
	 */
	for (cs = cf_subsection_find_next(config, NULL, "listen");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "listen")) {
		this = listen_parse(cs, NULL);
		if (!this) {
			listen_free(head);
			return -1;
		}

		*last = this;
		last = &(this->next);
	}

	/*
	 *	Check virtual servers for "listen" sections, too.
	 *
	 *	FIXME: Move to virtual server init?
	 */
	for (cs = cf_subsection_find_next(config, NULL, "server");
	     cs != NULL;
	     cs = cf_subsection_find_next(config, cs, "server")) {
		CONF_SECTION *subcs;
		const char *name2 = cf_section_name2(cs);
		
		for (subcs = cf_subsection_find_next(cs, NULL, "listen");
		     subcs != NULL;
		     subcs = cf_subsection_find_next(cs, subcs, "listen")) {
			this = listen_parse(subcs, name2);
			if (!this) {
				listen_free(head);
				return -1;
			}
			
			*last = this;
			last = &(this->next);
		} /* loop over "listen" directives in virtual servers */
	} /* loop over virtual servers */

add_sockets:
	/*
	 *	Print out which sockets we're listening on, and
	 *	add them to the event list.
	 */
	for (this = *head; this != NULL; this = this->next) {
#ifdef WITH_PROXY
		if (this->type == RAD_LISTEN_PROXY) {
			defined_proxy = 1;
		}

#endif
		event_new_fd(this);
	}

	/*
	 *	If we're proxying requests, open the proxy FD.
	 *	Otherwise, don't do anything.
	 */
#ifdef WITH_PROXY
	if ((mainconfig.proxy_requests == TRUE) &&
	    (*head != NULL) && !defined_proxy) {
		listen_socket_t *sock = NULL;
		int		port = 0;
		home_server	home;

		memset(&home, 0, sizeof(home));

		/*
		 *	
		 */
#ifdef WITH_TCP
		home.proto = IPPROTO_UDP;
#endif
		
		home.src_ipaddr = server_ipaddr;

		/*
		 *	Find the first authentication port,
		 *	and use it
		 */
		for (this = *head; this != NULL; this = this->next) {
			if (this->type == RAD_LISTEN_AUTH) {
				sock = this->data;
				if (home.src_ipaddr.af == AF_UNSPEC) {
					home.src_ipaddr = sock->my_ipaddr;
				}
				port = sock->my_port + 2;
				break;
			}
#ifdef WITH_ACCT
			if (this->type == RAD_LISTEN_ACCT) {
				sock = this->data;
				if (home.src_ipaddr.af == AF_UNSPEC) {
					home.src_ipaddr = sock->my_ipaddr;
				}
				port = sock->my_port + 1;
				break;
			}
#endif
		}

		/*
		 *	Address is still unspecified, use IPv4.
		 */
		if (home.src_ipaddr.af == AF_UNSPEC) {
			home.src_ipaddr.af = AF_INET;
			/* everything else is already set to zero */
		}

		this = listen_alloc("proxy");
		if (!this) return 0;	/* FIXME: memleak? */
		sock = this->data;
		home.ipaddr.af = home.src_ipaddr.af;
		/* everything else is already set to zero */

		if (!proxy_new_listener(&home, port)) {
			listen_free(head);
			return -1;
		}
	}
#endif

	/*
	 *	Haven't defined any sockets.  Die.
	 */
	if (!*head) return -1;


	return 0;
}

/*
 *	Free a linked list of listeners;
 */
void listen_free(rad_listen_t **head)
{
	rad_listen_t *this;

	if (!head || !*head) return;

	this = *head;
	while (this) {
		rad_listen_t *next = this->next;

		/*
		 *	Other code may have eaten the FD.
		 */
		if (this->fd >= 0) close(this->fd);

		if (this->frs->free) {
			this->frs->free(this);
		}

#ifdef WITH_TCP
		if ((this->type == RAD_LISTEN_AUTH) ||
#ifdef WITH_ACCT
		    (this->type == RAD_LISTEN_ACCT) ||
#endif
#ifdef WITH_PROXY
		    (this->type == RAD_LISTEN_PROXY)
#endif
			) {
			listen_socket_t *sock = this->data;
			rad_free(&sock->packet);
		}
#endif

		free(this->data);
		free(this);

		this = next;
	}

	*head = NULL;

#ifdef WITH_TCP
fr_tcp_radius_t *fr_listen2tcp(rad_listen_t *this)
{
	listen_socket_t *sock;

	if (!this || (this->type != RAD_LISTEN_PROXY) || !this->data) {
		return NULL;
	}

	sock = this->data;
	return sock->tcp;
}

rad_listen_t *proxy_new_tcp_listener(home_server *home)
{
	int i;
	fr_tcp_radius_t *tcp;
	struct sockaddr_storage	src;
	socklen_t sizeof_src = sizeof(src);
	rad_listen_t *this;
	listen_socket_t *sock;

	if (!home ||
	    ((home->max_connections > 0) &&
	     (home->num_connections >= home->max_connections))) {
		DEBUG("WARNING: Home server has too many open connections (%d)",
		      home->max_connections);
		return NULL;
	}

	this = NULL;

	/*
	 *	FIXME: Move to RBTrees.
	 */
	for (i = 0; i < home->max_connections; i++) {
		if (home->listeners[i]) continue;

		this = home->listeners[i] = listen_alloc(RAD_LISTEN_PROXY);
		if (!this) {
			DEBUG("WARNING: Failed allocating memory");
			return NULL;
		}
		break;
	}

	if (!this) {
		DEBUG("WARNING: Failed to find a free connection slot");
		return NULL;
	}
	sock = this->data;

	tcp = sock->tcp = rad_malloc(sizeof(*tcp));
	memset(tcp, 0, sizeof(*tcp));

	/*
	 *	Initialize th
	 *
	 *	Open a new socket...
	 *
	 *	Do stuff...
	 */
	tcp->dst_ipaddr = home->ipaddr;
	tcp->dst_port = home->port;
	tcp->lifetime = home->lifetime;
	tcp->opened = time(NULL);	

	/*
	 *	FIXME: connect() is blocking!
	 *	We do this with the proxy mutex locked, which may
	 *	cause large delays!
	 *
	 *	http://www.developerweb.net/forum/showthread.php?p=13486
	 */
	this->fd = tcp->fd = fr_tcp_client_socket(&tcp->dst_ipaddr, tcp->dst_port);
	if (tcp->fd < 0) {
		listen_free(&this);
		DEBUG("WARNING: Failed opening socket to home server");
		return NULL;
	}
	memset(&src, 0, sizeof_src);
	if (getsockname(tcp->fd, (struct sockaddr *) &src, &sizeof_src) < 0) {
		close(tcp->fd);
		listen_free(&this);
		return NULL;
	}

	if (!fr_sockaddr2ipaddr(&src, sizeof_src,
				&tcp->src_ipaddr, &tcp->src_port)) {
		close(tcp->fd);
		listen_free(&this);
		return NULL;
	}

	/*
	 *	Fill in socket information.
	 */
	sock->proto = IPPROTO_TCP;
	sock->tcp = tcp;

	sock->ipaddr = tcp->src_ipaddr;
	sock->port = tcp->src_port;

	/*
	 *	Don't ask.  Just don't ask.
	 */
	sock->src_ipaddr = tcp->dst_ipaddr;
	sock->src_port = tcp->dst_port;
	sock->home = home;
	sock->home->num_connections++;

#if 0
	this->recv = proxy_socket_tcp_recv;
#endif

	/*
	 *	Tell the event handler about the new socket.
	 *
	 *	It keeps track of "this", so we don't have to insert
	 *	it into the main list of listeners.
	 */
	event_new_fd(this);

	return this;
}

void proxy_close_tcp_listener(rad_listen_t *listener)
{
	int i;
	listen_socket_t *sock = listener->data;
	
	/*
	 *	This is the second time around for the socket.  Free
	 *	the memory now.
	 */
	if (listener->status != RAD_LISTEN_STATUS_KNOWN) {
		listen_free(&listener);
		return;
	}

	listener->status = RAD_LISTEN_STATUS_CLOSED;
	event_new_fd(listener);
	
	/*
	 *	Find the home server, and mark this listener as
	 *	no longer being active.
	 */
	for (i = 0; i < sock->home->max_connections; i++) {
		if (sock->home->listeners[i] == listener) {
			sock->home->listeners[i] = NULL;
			sock->home->num_connections--;
			break;
		}
	}

	/*
	 *	There are still one or more requests using this socket.
	 *	leave it marked as "closed", but don't free it.  When the
	 *	last requeast using it is cleaned up, it will be deleted.
	 */
	if (sock->tcp->used > 0) return;
	
	listen_free(&listener);
}
#endif

#ifdef WITH_STATS
rad_listen_t *listener_find_byipaddr(const fr_ipaddr_t *ipaddr, int port)
{
	rad_listen_t *this;

	for (this = mainconfig.listen; this != NULL; this = this->next) {
		listen_socket_t *sock;

		/*
		 *	FIXME: For TCP, ignore the *secondary*
		 *	listeners associated with the main socket.
		 */
		if ((this->type != RAD_LISTEN_AUTH) &&
		    (this->type != RAD_LISTEN_ACCT)) continue;
		
		sock = this->data;

		if ((sock->my_port == port) &&
		    (fr_ipaddr_cmp(ipaddr, &sock->my_ipaddr) == 0)) {
			return this;
		}

		if ((sock->my_port == port) &&
		    ((sock->my_ipaddr.af == AF_INET) &&
		     (sock->my_ipaddr.ipaddr.ip4addr.s_addr == INADDR_ANY))) {
			return this;
		}

#ifdef HAVE_STRUCT_SOCKADDR_IN6
		if ((sock->my_port == port) &&
		    (sock->my_ipaddr.af == AF_INET6) &&
		    (IN6_IS_ADDR_UNSPECIFIED(&sock->my_ipaddr.ipaddr.ip6addr))) {
			return this;
		}
#endif
	}

	return NULL;
}
