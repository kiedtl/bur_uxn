// d0: reserved
// d1: ^^
// d2: current
// d3: length
// d4: ^^
// d5: init + connect
// d6: ^^
// d7: send
// d8: ^^
// d9: recv
// da: ^^
// db: close
// dc:
// dd:
// de:
// df: status

#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tls.h>
#include <unistd.h>

#include "../uxn.h"
#include "net.h"

typedef struct Connection {
	int fd;
	struct tls *tls;
	_Bool is_secure;
} conn_t;

Uint8 current = 0;
Uint8 status = 0;
Uint16 length = 0;
conn_t connections[16] = {0};

static _Bool
conn_active(conn_t *c)
{
	return (c->is_secure && c->tls != NULL) || (c->fd != 0);
}

static _Bool
conn_tls_init(conn_t *c)
{
	struct tls_config *tlscfg = tls_config_new();
	if (!tlscfg) {
		status = NET_ERR_TLS_CONFIG;
		return false; /* tls_config_new error */
	}

	if (tls_config_set_ciphers(tlscfg, "compat") != 0) {
		status = NET_ERR_TLS_CONFIG;
		return false; /* tls_config_set_ciphers error */
	}

	/* FIXME: right way to allow self-signed certs? */
	tls_config_insecure_noverifycert(tlscfg);

	c->tls = tls_client();
	if (!tlscfg) {
		status = NET_ERR_TLS_INIT;
		return false; /* tls_client error */
	}

	if (tls_configure(c->tls, tlscfg) != 0) {
		status = NET_ERR_TLS_CONFIGURE;
		return false; /* tls_configure error */
	}

	tls_config_free(tlscfg);
	status = NET_OK;

	return true;
}

static void
conn_conn(conn_t *c, _Bool is_secure, char *host, Uint16 port)
{
	if (!conn_active(c))
		if (!conn_tls_init(c))
			return;
	c->is_secure = is_secure;

	struct addrinfo hints = {
		.ai_protocol = IPPROTO_TCP,
		.ai_socktype = SOCK_STREAM,
		.ai_family = AF_UNSPEC,
	};
	struct addrinfo *res, *r;
	int fd = -1;

	char port_str[6] = {0}; // 6 = 65535 (5 chars) + nul
	sprintf((char *)&port_str, "%hd", port);

	/* printf("connecting to '%s' on port '%s'\n", host, (char *)&port_str); */
	if (getaddrinfo(host, (char *)&port_str, &hints, &res) != 0) {
		status = NET_ERR_RESOLVE;
		/* printf("couldn't resolve\n"); */
		return; /* failed to resolve */
	}

	for(r = res; r != NULL; r = r->ai_next) {
		if((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1)
			continue;
		if(connect(fd, r->ai_addr, r->ai_addrlen) == 0)
			break;
		close(fd);
	}

	freeaddrinfo(res);

	if (r == NULL) {
		/* printf("connection error\n"); */
		status = NET_ERR_CONNECT;
		return; /* can't connect */
	}

	if (c->is_secure) {
		if (tls_connect_socket(c->tls, fd, host) != 0) {
			/* printf("tls upgrade error\n"); */
			status = NET_ERR_TLS_UPGRADE;
			return; /* tls: socket upgrade failed */
		}

		if (tls_handshake(c->tls) != 0) {
			/* printf("tls handshake error: %s\n", tls_error(client[current])); */
			status = NET_ERR_TLS_HANDSHAKE;
			return; /* tls: handshake failed */
		}
	}

	/* printf("all good\n"); */
	status = NET_OK;
	c->fd = fd;
}

static void
conn_done(conn_t *c)
{
	if (!conn_active(c)) {
		status = NET_ERR_NOT_INITED;
		return;
	}

	if (c->is_secure) tls_close(c->tls);
	close(c->fd);
	if (c->is_secure) tls_free(c->tls);

	c->fd = 0;
	c->tls = NULL;
	c->is_secure = false;
}

static void
conn_recv(conn_t *c, Uint8 *bufsrv, Uint16 sz)
{
	if (!conn_active(c)) {
		length = 0;
		status = NET_ERR_NOT_INITED;
		return;
	}

	ssize_t r = c->is_secure ? tls_read(c->tls, bufsrv, sz) : read(c->fd, bufsrv, sz);

	if (c->is_secure && r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT) {
		length = 0;
		status = NET_OK_RETRY;
		return;
	} else if (r < 0) {
		if (errno != EINTR) { /* FIXME: not sure if errno is valid when tls is active? */
			char *e = c->is_secure ? tls_error(c->tls) : strerror(errno);
			fprintf(stderr, "DEVICE(net): tls error: %s\n", e);
			length = 0;
			status = NET_ERR_SYSTEM;
			return;
		}
		length = 0;
		status = NET_OK_RETRY;
		return;
	}

	if (r == 0)
		status = NET_OK_NODATA;

	length = r;
}

static void
conn_send(conn_t *c, Uint8 *data, Uint16 len)
{
	if (!conn_active(c)) {
		status = NET_ERR_NOT_INITED;
		return;
	}

	while (len) {
		ssize_t r = -1;

		if (c->is_secure)
			r = tls_write(c->tls, data, len);
		else
			r = send(c->fd, data, len, 0);

		if (c->is_secure && r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT) {
			status = NET_OK_RETRY;
			continue;
		} else if (r < 0) {
			status = NET_ERR_SYSTEM;
			return;
		}

		data += r; len -= r;
	}

	status = NET_OK;
}

Uint8
net_dei(Uxn *u, Uint8 addr)
{
	switch (addr) {
	break; case 0xd2: return current;
	break; case 0xd3: return (Uint8)(length >> 8);
	break; case 0xd4: return (Uint8)(length & 0xFF);
	break; case 0xdf: return status;
	break; default: return u->dev[addr];
	}
}

void
net_deo(Uxn *u, Uint8 addr)
{
	conn_t *c = &connections[current];

	switch (addr) {
	break; case 0x4: {
		length = PEEK2(&u->dev[0xd3]);
	} break; case 0x6: {
		Uint16 addr = PEEK2(&u->dev[0xd5]);
		Uint8 use_tls = PEEK2(&u->ram[addr]);
		Uint16 port = PEEK2(&u->ram[addr + 1]);
		Uint16 host_addr = PEEK2(&u->ram[addr + 3]);
		char *host = (char *)&u->ram[host_addr];
		conn_conn(c, use_tls, host, port);
	} break; case 0x8: {
		Uint16 addr = PEEK2(&u->dev[0xd7]);
		conn_send(c, &u->ram[addr], length);
	} break; case 0xa: {
		Uint16 addr = PEEK2(&u->dev[0xd9]);
		conn_recv(c, &u->ram[addr], length);
	} break; case 0xb: {
		conn_done(c);
	} break;
	}
}
