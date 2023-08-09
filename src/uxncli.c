#include <stdio.h>
#include <stdlib.h>

#include "uxn.h"
#include "devices/system.h"
#include "devices/console.h"
#include "devices/file.h"
#include "devices/datetime.h"

/*
Copyright (c) 2021-2023 Devine Lu Linvega, Andrew Alderwick

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE.
*/

Uint16 dev_vers[0x10], dei_mask[0x10], deo_mask[0x10];

Uint8
emu_dei(Uxn *u, Uint8 addr)
{
	switch(addr & 0xf0) {
	case 0xc0: return datetime_dei(u, addr);
	}
	return u->dev[addr];
}

void
emu_deo(Uxn *u, Uint8 addr)
{
	Uint8 p = addr & 0x0f, d = addr & 0xf0;
	switch(d) {
	case 0x00: system_deo(u, &u->dev[d], p); break;
	case 0x10: console_deo(&u->dev[d], p); break;
	case 0xa0: file_deo(0, u->ram, &u->dev[d], p); break;
	case 0xb0: file_deo(1, u->ram, &u->dev[d], p); break;
	}
}

int
main(int argc, char **argv)
{
	Uxn u;
	int i = 1;
	if(i == argc)
		return system_error("usage", "uxncli [-v] file.rom [args..]");
	/* Connect Varvara */
	system_connect(0x0, SYSTEM_VERSION, SYSTEM_DEIMASK, SYSTEM_DEOMASK);
	system_connect(0x1, CONSOLE_VERSION, CONSOLE_DEIMASK, CONSOLE_DEOMASK);
	system_connect(0xa, FILE_VERSION, FILE_DEIMASK, FILE_DEOMASK);
	system_connect(0xb, FILE_VERSION, FILE_DEIMASK, FILE_DEOMASK);
	system_connect(0xc, DATETIME_VERSION, DATETIME_DEIMASK, DATETIME_DEOMASK);
	/* Read flags */
	if(argv[i][0] == '-' && argv[i][1] == 'v')
		return system_version("Uxncli - Console Varvara Emulator", "9 Aug 2023");
	/* Continue.. */
	if(!uxn_boot(&u, (Uint8 *)calloc(0x10000 * RAM_PAGES, sizeof(Uint8))))
		return system_error("Boot", "Failed");
	/* Load rom */
	if(!system_load(&u, argv[i++]))
		return system_error("Load", "Failed");
	/* Game Loop */
	u.dev[0x17] = argc - i;
	if(uxn_eval(&u, PAGE_PROGRAM)) {
		for(; i < argc; i++) {
			char *p = argv[i];
			while(*p) console_input(&u, *p++, CONSOLE_ARG);
			console_input(&u, '\n', i == argc - 1 ? CONSOLE_END : CONSOLE_EOA);
		}
		while(!u.dev[0x0f]) {
			int c = fgetc(stdin);
			if(c == EOF) break;
			console_input(&u, (Uint8)c, CONSOLE_STD);
		}
	}
	free(u.ram);
	return u.dev[0x0f] & 0x7f;
}
