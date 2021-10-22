#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include "uxn.h"

/*
Copyright (c) 2021 Devine Lu Linvega

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

#pragma mark - Core

static Device *devsystem, *devconsole;

static int
error(char *msg, const char *err)
{
	fprintf(stderr, "Error %s: %s\n", msg, err);
	return 0;
}

static void
inspect(Stack *s, char *name)
{
	Uint8 x, y;
	fprintf(stderr, "\n%s\n", name);
	for(y = 0; y < 0x04; ++y) {
		for(x = 0; x < 0x08; ++x) {
			Uint8 p = y * 0x08 + x;
			fprintf(stderr,
				p == s->ptr ? "[%02x]" : " %02x ",
				s->dat[p]);
		}
		fprintf(stderr, "\n");
	}
}

#pragma mark - Devices

static int
system_talk(Device *d, Uint8 b0, Uint8 w)
{
	if(!w) { /* read */
		switch(b0) {
		case 0x2: d->dat[0x2] = d->u->wst.ptr; break;
		case 0x3: d->dat[0x3] = d->u->rst.ptr; break;
		}
	} else { /* write */
		switch(b0) {
		case 0x2: d->u->wst.ptr = d->dat[0x2]; break;
		case 0x3: d->u->rst.ptr = d->dat[0x3]; break;
		case 0xe:
			inspect(&d->u->wst, "Working-stack");
			inspect(&d->u->rst, "Return-stack");
			break;
		case 0xf: return 0;
		}
	}
	return 1;
}

static int
console_talk(Device *d, Uint8 b0, Uint8 w)
{
	if(b0 == 0x1)
		d->vector = peek16(d->dat, 0x0);
	if(w && b0 > 0x7)
		write(b0 - 0x7, (char *)&d->dat[b0], 1);
	return 1;
}

static int
file_talk(Device *d, Uint8 b0, Uint8 w)
{
	Uint8 read = b0 == 0xd;
	if(w && (read || b0 == 0xf)) {
		char *name = (char *)&d->mem[peek16(d->dat, 0x8)];
		Uint16 result = 0, length = peek16(d->dat, 0xa);
		long offset = (peek16(d->dat, 0x4) << 16) + peek16(d->dat, 0x6);
		Uint16 addr = peek16(d->dat, b0 - 1);
		FILE *f = fopen(name, read ? "rb" : (offset ? "ab" : "wb"));
		if(f) {
			if(fseek(f, offset, SEEK_SET) != -1)
				result = read ? fread(&d->mem[addr], 1, length, f) : fwrite(&d->mem[addr], 1, length, f);
			fclose(f);
		}
		poke16(d->dat, 0x2, result);
	}
	return 1;
}

static int
datetime_talk(Device *d, Uint8 b0, Uint8 w)
{
	time_t seconds = time(NULL);
	struct tm *t = localtime(&seconds);
	t->tm_year += 1900;
	poke16(d->dat, 0x0, t->tm_year);
	d->dat[0x2] = t->tm_mon;
	d->dat[0x3] = t->tm_mday;
	d->dat[0x4] = t->tm_hour;
	d->dat[0x5] = t->tm_min;
	d->dat[0x6] = t->tm_sec;
	d->dat[0x7] = t->tm_wday;
	poke16(d->dat, 0x08, t->tm_yday);
	d->dat[0xa] = t->tm_isdst;
	(void)b0;
	(void)w;
	return 1;
}

static int
nil_talk(Device *d, Uint8 b0, Uint8 w)
{
	(void)d;
	(void)b0;
	(void)w;
	return 1;
}

#pragma mark - Generics

static const char *errors[] = {"underflow", "overflow", "division by zero"};

int
uxn_halt(Uxn *u, Uint8 error, char *name, int id)
{
	fprintf(stderr, "Halted: %s %s#%04x, at 0x%04x\n", name, errors[error - 1], id, u->ram.ptr);
	return 0;
}

static int
console_input(Uxn *u, char c)
{
	devconsole->dat[0x2] = c;
	return uxn_eval(u, devconsole->vector);
}

static void
run(Uxn *u)
{
	Uint16 vec;
	while((!u->dev[0].dat[0xf]) && (read(0, &devconsole->dat[0x2], 1) > 0)) {
		vec = peek16(devconsole->dat, 0);
		if(!vec) vec = u->ram.ptr; /* continue after last BRK */
		uxn_eval(u, vec);
	}
}

static int
load(Uxn *u, char *filepath)
{
	FILE *f;
	if(!(f = fopen(filepath, "rb")))
		return 0;
	fread(u->ram.dat + PAGE_PROGRAM, sizeof(u->ram.dat) - PAGE_PROGRAM, 1, f);
	fprintf(stderr, "Loaded %s\n", filepath);
	return 1;
}

int
main(int argc, char **argv)
{
	Uxn u;
	int i, loaded = 0;

	if(!uxn_boot(&u))
		return error("Boot", "Failed");

	/* system   */ devsystem = uxn_port(&u, 0x0, system_talk);
	/* console  */ devconsole = uxn_port(&u, 0x1, console_talk);
	/* empty    */ uxn_port(&u, 0x2, nil_talk);
	/* empty    */ uxn_port(&u, 0x3, nil_talk);
	/* empty    */ uxn_port(&u, 0x4, nil_talk);
	/* empty    */ uxn_port(&u, 0x5, nil_talk);
	/* empty    */ uxn_port(&u, 0x6, nil_talk);
	/* empty    */ uxn_port(&u, 0x7, nil_talk);
	/* empty    */ uxn_port(&u, 0x8, nil_talk);
	/* empty    */ uxn_port(&u, 0x9, nil_talk);
	/* file     */ uxn_port(&u, 0xa, file_talk);
	/* datetime */ uxn_port(&u, 0xb, datetime_talk);
	/* empty    */ uxn_port(&u, 0xc, nil_talk);
	/* empty    */ uxn_port(&u, 0xd, nil_talk);
	/* empty    */ uxn_port(&u, 0xe, nil_talk);
	/* empty    */ uxn_port(&u, 0xf, nil_talk);

	for(i = 1; i < argc; ++i) {
		if(!loaded++) {
			if(!load(&u, argv[i]))
				return error("Load", "Failed");
			if(!uxn_eval(&u, PAGE_PROGRAM))
				return error("Init", "Failed");
		} else {
			char *p = argv[i];
			while(*p) console_input(&u, *p++);
			console_input(&u, '\n');
		}
	}
	if(!loaded)
		return error("Input", "Missing");

	run(&u);

	return 0;
}
