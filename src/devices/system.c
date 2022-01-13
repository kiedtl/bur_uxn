#include "../uxn.h"
#include "system.h"

#include <stdio.h>

/*
Copyright (c) 2022 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

static const char *errors[] = {
	"Working-stack underflow",
	"Return-stack underflow",
	"Working-stack overflow",
	"Return-stack overflow",
	"Working-stack division by zero",
	"Return-stack division by zero"};

static void
inspect(Stack *s, char *name)
{
	Uint8 x, y;
	fprintf(stderr, "\n%s\n", name);
	for(y = 0; y < 0x04; y++) {
		for(x = 0; x < 0x08; x++) {
			Uint8 p = y * 0x08 + x;
			fprintf(stderr,
				p == s->ptr ? "[%02x]" : " %02x ",
				s->dat[p]);
		}
		fprintf(stderr, "\n");
	}
}

int
uxn_halt(Uxn *u, Uint8 error, Uint16 addr)
{
	Device *d = &u->dev[0];
	Uint16 vec = GETVECTOR(d);
	DEVPOKE16(0x4, addr);
	d->dat[0x6] = error;
	if(vec) {
		/* need to rearm to run System/vector again */
		d->dat[0] = 0;
		d->dat[1] = 0;
		if(error != 2) /* working stack overflow has special treatment */
			vec += 0x0004;
		return uxn_eval(u, vec);
	}
	fprintf(stderr, "Halted: %s#%04x, at 0x%04x\n", errors[error], u->ram[addr], addr);
	return 0;
}

/* IO */

Uint8
system_dei(Device *d, Uint8 port)
{
	switch(port) {
	case 0x2: return d->u->wst.ptr;
	case 0x3: return d->u->rst.ptr;
	default: return d->dat[port];
	}
}

void
system_deo(Device *d, Uint8 port)
{
	switch(port) {
	case 0x2: d->u->wst.ptr = d->dat[port]; break;
	case 0x3: d->u->rst.ptr = d->dat[port]; break;
	case 0xe:
		inspect(&d->u->wst, "Working-stack");
		inspect(&d->u->rst, "Return-stack");
		break;
	default: system_deo_special(d, port);
	}
}
