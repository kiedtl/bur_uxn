/*
 * Copyright (c) 2024 Kiëd Llaentenn
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE.
*/

#define NET_VERSION 1
#define NET_DEOMASK 0xFFFF // TODO
#define NET_DEIMASK 0xFFFF // TODO

#define NET_OK_RETRY                          2
#define NET_OK                                1
#define NET_OK_NODATA                         0

#define NET_ERR_TLS_CONFIG    (unsigned char)-1
#define NET_ERR_TLS_INIT      (unsigned char)-2
#define NET_ERR_TLS_CONFIGURE (unsigned char)-1
#define NET_ERR_RESOLVE       (unsigned char)-3
#define NET_ERR_CONNECT       (unsigned char)-4
#define NET_ERR_TLS_UPGRADE   (unsigned char)-5
#define NET_ERR_TLS_HANDSHAKE (unsigned char)-6
#define NET_ERR_SYSTEM        (unsigned char)-7
#define NET_ERR_NOT_INITED    (unsigned char)-8 // TODO: get rid of this
#define NET_ERR_UNKNOWN       (unsigned char)-9

Uint8 net_dei(Uxn *u, Uint8 addr);
void net_deo(Uxn *u, Uint8 addr);
