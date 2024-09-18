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

int connections[16] = {0};
struct tls *client[16] = {0};
Uint8 current = 0;
Uint8 status = 0;
Uint16 length = 0;

static _Bool
conn_init(void)
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

	client[current] = tls_client();
	if (!tlscfg) {
		status = NET_ERR_TLS_INIT;
		return false; /* tls_client error */
	}

	if (tls_configure(client[current], tlscfg) != 0) {
		status = NET_ERR_TLS_CONFIGURE;
		return false; /* tls_configure error */
	}

	tls_config_free(tlscfg);
	status = NET_OK;

	return true;
}

static void
conn_conn(char *host, Uint16 port)
{
	if (client[current] == NULL)
		if (!conn_init())
			return;

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

	if (tls_connect_socket(client[current], fd, host) != 0) {
		/* printf("tls upgrade error\n"); */
		status = NET_ERR_TLS_UPGRADE;
		return; /* tls: socket upgrade failed */
	}

	if (tls_handshake(client[current]) != 0) {
		/* printf("tls handshake error: %s\n", tls_error(client[current])); */
		status = NET_ERR_TLS_HANDSHAKE;
		return; /* tls: handshake failed */
	}

	/* printf("all good\n"); */
	status = NET_OK;
	connections[current] = fd;
}

static void
conn_done()
{
	if (client[current] == NULL) {
		status = NET_ERR_NOT_INITED;
		return;
	}
	tls_close(client[current]);
	close(connections[current]);
	tls_free(client[current]);
	client[current] = NULL;
}

static void
conn_recv(Uint8 *bufsrv, Uint16 sz)
{
	if (client[current] == NULL) {
		length = 0;
		status = NET_ERR_NOT_INITED;
		return;
	}

	ssize_t r = tls_read(client[current], bufsrv, sz);

	if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT) {
		/* should never happen -- would always be fault of emulator
		 */
		fprintf(stderr, "/dev/sda is on fire\n");
		length = 0;
		status = NET_ERR_UNKNOWN;
		return;
	} else if (r < 0) {
		if (errno != EINTR) {
			fprintf(stderr, "DEVICE(net): tls error: %s\n", tls_error(client[current]));
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
conn_send(Uint8 *data, Uint16 len)
{
	if (client[current] == NULL) {
		status = NET_ERR_NOT_INITED;
		return;
	}

	while (len) {
		ssize_t r = -1;

		r = tls_write(client[current], data, len);

		if (r == TLS_WANT_POLLIN || r == TLS_WANT_POLLOUT) {
			/* should never happen -- would always be fault of emulator
			 */
			fprintf(stderr, "/dev/sda is on fire\n");
			status = NET_ERR_UNKNOWN;
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
	switch (addr) {
	break; case 0x4: {
		length = PEEK2(&u->dev[0xd3]);
	} break; case 0x6: {
		Uint16 addr = PEEK2(&u->dev[0xd5]);
		Uint8 tls = PEEK2(&u->ram[addr]); // TODO
		Uint16 port = PEEK2(&u->ram[addr + 1]);
		Uint16 host_addr = PEEK2(&u->ram[addr + 3]);
		conn_conn((char *)&u->ram[host_addr], port);
	} break; case 0x8: {
		Uint16 addr = PEEK2(&u->dev[0xd7]);
		conn_send(&u->ram[addr], length);
	} break; case 0xa: {
		Uint16 addr = PEEK2(&u->dev[0xd9]);
		conn_recv(&u->ram[addr], length);
	} break; case 0xb: {
		conn_done();
	} break;
	}
}
