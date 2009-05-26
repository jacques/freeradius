/*
 * coa.c	Change of Authorization && Disconnect packets.
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
 * Copyright 2000,2006  The FreeRADIUS server project
 * Copyright 2000  Miquel van Smoorenburg <miquels@cistron.nl>
 * Copyright 2009 Alan DeKok <aland@deployingradius.com>
 */

#include <freeradius-devel/ident.h>
RCSID("$Id$")

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/rad_assert.h>

#include <ctype.h>

#ifdef WITH_COA
/*
 *	Process and reply to a server-status request.
 */
static int coa_status_server(REQUEST *request)
{
	int rcode = RLM_MODULE_OK;
	DICT_VALUE *dval;

	dval = dict_valbyname(PW_AUTZ_TYPE, "Status-Server");
	if (dval) {
		rcode = module_recv_coa(dval->value, request);
	} else {
		rcode = RLM_MODULE_OK;
	}
	
	switch (rcode) {
	case RLM_MODULE_OK:
	case RLM_MODULE_UPDATED:
		request->reply->code = PW_COA_ACK;
		break;
		
	default:
		request->reply->code = 0; /* don't reply */
		break;
	}

	return 0;
}


/*
 *	Receive a CoA packet.
 */
static int rad_coa_recv(REQUEST *request)
{
	int rcode = RLM_MODULE_OK;
	int ack, nak;
	VALUE_PAIR *vp;

	/*
	 *	Get the correct response
	 */
	switch (request->packet->code) {
	case PW_COA_REQUEST:
		ack = PW_COA_ACK;
		nak = PW_COA_NAK;
		break;

	case PW_DISCONNECT_REQUEST:
		ack = PW_DISCONNECT_ACK;
		nak = PW_DISCONNECT_NAK;
		break;

	default:		/* shouldn't happen */
		return RLM_MODULE_FAIL;
	}

#ifdef WITH_PROXY
#define WAS_PROXIED (request->proxy)
#else
#define WAS_PROXIED (0)
#endif

	if (!WAS_PROXIED) {
		/*
		 *	RFC 5176 Section 3.3.  If we have a CoA-Request
		 *	with Service-Type = Authorize-Only, it MUST
		 *	have a State attribute in it.
		 */
		vp = pairfind(request->packet->vps, PW_SERVICE_TYPE);
		if (request->packet->code == PW_COA_REQUEST) {
			if (vp && (vp->vp_integer == 17)) {
				vp = pairfind(request->packet->vps, PW_STATE);
				if (!vp || (vp->length == 0)) {
					RDEBUG("ERROR: CoA-Request with Service-Type = Authorize-Only MUST contain a State attribute");
					request->reply->code = PW_COA_NAK;
					return RLM_MODULE_FAIL;
				}
			}
		} else if (vp) {
			/*
			 *	RFC 5176, Section 3.2.
			 */
			RDEBUG("ERROR: Disconnect-Request MUST NOT contain a Service-Type attribute");
			request->reply->code = PW_DISCONNECT_NAK;
			return RLM_MODULE_FAIL;
		}

		rcode = module_recv_coa(0, request);
		switch (rcode) {
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			request->reply->code = nak;
			break;
			
		case RLM_MODULE_HANDLED:
			return rcode;
			
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			request->reply->code = ack;
			break;
		}
	} else {
		/*
		 *	Start the reply code with the proxy reply
		 *	code.
		 */
		request->reply->code = request->proxy_reply->code;
	}

	/*
	 *	Copy State from the request to the reply.
	 *	See RFC 5176 Section 3.3.
	 */
	vp = paircopy2(request->packet->vps, PW_STATE);
	if (vp) pairadd(&request->reply->vps, vp);

	/*
	 *	We may want to over-ride the reply.
	 */
	rcode = module_send_coa(0, request);
	switch (rcode) {
		/*
		 *	We need to send CoA-NAK back if Service-Type
		 *	is Authorize-Only.  Rely on the user's policy
		 *	to do that.  We're not a real NAS, so this
		 *	restriction doesn't (ahem) apply to us.
		 */
		case RLM_MODULE_FAIL:
		case RLM_MODULE_INVALID:
		case RLM_MODULE_REJECT:
		case RLM_MODULE_USERLOCK:
		default:
			/*
			 *	Over-ride an ACK with a NAK
			 */
			request->reply->code = nak;
			break;
			
		case RLM_MODULE_HANDLED:
			return rcode;
			
		case RLM_MODULE_NOOP:
		case RLM_MODULE_NOTFOUND:
		case RLM_MODULE_OK:
		case RLM_MODULE_UPDATED:
			/*
			 *	Do NOT over-ride a previously set value.
			 *	Otherwise an "ok" here will re-write a
			 *	NAK to an ACK.
			 */
			if (request->reply->code == 0) {
				request->reply->code = ack;
			}
			break;

	}

	return RLM_MODULE_OK;
}

/*
 *	Check if an incoming request is "ok"
 *
 *	It takes packets, not requests.  It sees if the packet looks
 *	OK.  If so, it does a number of sanity checks on it.
  */
static int coa_socket_recv(rad_listen_t *listener,
			    RAD_REQUEST_FUNP *pfun, REQUEST **prequest)
{
	ssize_t		rcode;
	int		code, src_port;
	RADIUS_PACKET	*packet;
	RAD_REQUEST_FUNP fun = NULL;
	char		buffer[128];
	RADCLIENT	*client;
	fr_ipaddr_t	src_ipaddr;

	rcode = rad_recv_header(listener->fd, &src_ipaddr, &src_port, &code);
	if (rcode < 0) return 0;

	RAD_STATS_TYPE_INC(listener, total_requests);

	if (rcode < 20) {	/* AUTH_HDR_LEN */
		RAD_STATS_TYPE_INC(listener, total_malformed_requests);
		return 0;
	}

	if ((client = client_listener_find(listener,
					   &src_ipaddr, src_port)) == NULL) {
		rad_recv_discard(listener->fd);
		RAD_STATS_TYPE_INC(listener, total_invalid_requests);

		if (debug_flag > 0) {
			char name[1024];

			listener->print(listener, name, sizeof(name));

			/*
			 *	This is debugging rather than logging, so that
			 *	DoS attacks don't affect us.
			 */
			DEBUG("Ignoring request to %s from unknown client %s port %d",
			      name,
			      inet_ntop(src_ipaddr.af, &src_ipaddr.ipaddr,
					buffer, sizeof(buffer)), src_port);
		}

		return 0;
	}

	/*
	 *	Some sanity checks, based on the packet code.
	 */
	switch(code) {
	case PW_COA_REQUEST:
	case PW_DISCONNECT_REQUEST:
		fun = rad_coa_recv;
		break;

	default:
		rad_recv_discard(listener->fd);
		DEBUG("Invalid packet code %d sent to coa port from client %s port %d : IGNORED",
		      code, client->shortname, src_port);
		return 0;
		break;
	} /* switch over packet types */

	/*
	 *	Now that we've sanity checked everything, receive the
	 *	packet.
	 */
	packet = rad_recv(listener->fd, client->message_authenticator);
	if (!packet) {
		RAD_STATS_TYPE_INC(listener, total_malformed_requests);
		DEBUG("%s", fr_strerror());
		return 0;
	}

	if (!received_request(listener, packet, prequest, client)) {
		rad_free(&packet);
		return 0;
	}

	*pfun = fun;
	return 1;
}

/*
 *	Send a coa response packet
 */
static int coa_socket_send(rad_listen_t *listener, REQUEST *request)
{
	rad_assert(request->listener == listener);
	rad_assert(listener->send == coa_socket_send);

	return rad_send(request->reply, request->packet,
			request->client->secret);
}

static int coa_socket_encode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (!request->reply->code) return 0;

	rad_encode(request->reply, request->packet,
		   request->client->secret);
	rad_sign(request->reply, request->packet,
		 request->client->secret);

	return 0;
}

static int coa_socket_decode(UNUSED rad_listen_t *listener, REQUEST *request)
{
	if (rad_verify(request->packet, NULL,
		       request->client->secret) < 0) {
		return -1;
	}

	return rad_decode(request->packet, NULL,
			  request->client->secret);
}

frs_module_t frs_coa =	{
	FRS_MODULE_INIT, RAD_LISTEN_AUTH, "coa",
	listen_socket_parse, NULL,
	coa_socket_recv, coa_socket_send,
	listen_socket_print, coa_socket_encode, coa_socket_decode
};
#endif
