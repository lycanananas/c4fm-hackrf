/* SPDX-License-Identifier: MIT */
/* Hosts the translated DM-32UV codec: loads it into the emulated memory and calls it the way RadioFoundry's
 * platform/hrc7000/vocoder.c does on the radio (docs/spec/codec-dm32.md, "Calling convention", "C. Codec state init"). */
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ambe.h"
#include "cskyrt.h"

uint8_t csky_ram[RAM_SIZE];
uint8_t csky_modem[MODEM_SIZE];

/* where things live in the emulated RAM (above any build's codec code, which ends below 0x30000) */
#define E_ADDR		0x80000u	/* encoder state, 0x1C00 bytes */
#define D_ADDR		0x84000u	/* decoder state, 0x1800 bytes */
#define STATE_BYTES	0x2000u
#define EBITS_ADDR	0x88000u	/* 72 halfwords */
#define DBITS_ADDR	0x88100u
#define EPCM_ADDR	0x88200u	/* 160 halfwords */
#define DPCM_ADDR	0x88400u
#define STACK_TOP	0xF0000u
#define HALF		(AMBE_FRAME_SAMPLES / 2)
#define BUDGET		50000000ull

static uint32_t run_addr, ent_decode, ent_encode, ent_dec_init, ent_dec_set, ent_enc_init, ent_enc_set, ent_fec_init;
static uint32_t enc_flags = AMBE_ENC_DEFAULT;
static int loaded, enc_ready, dec_ready;
static jmp_buf fault_jmp;
static char err[256];

const char *ambe_error(void) { return err; }

void csky_fault(uint32_t addr, const char *what)
{
	snprintf(err, sizeof err, "codec fault at 0x%08x: %s", addr, what);
	longjmp(fault_jmp, 1);
}

static long json_int(const char *js, const char *key)
{
	char pat[64];
	snprintf(pat, sizeof pat, "\"%s\":", key);
	const char *p = strstr(js, pat);
	if (!p) {
		return -1;
	}
	return strtol(p + strlen(pat), NULL, 0);
}

static long read_file(const char *dir, const char *name, uint8_t *dst, long max)
{
	char path[1024];
	snprintf(path, sizeof path, "%s/%s", dir, name);
	FILE *f = fopen(path, "rb");
	if (!f) {
		snprintf(err, sizeof err, "cannot open %s (run tools/extract_codec.py first)", path);
		return -1;
	}
	long n = (long)fread(dst, 1, (size_t)max, f);
	fclose(f);
	return n;
}

int ambe_load(const char *dir)
{
	static char js[4096];
	long n = read_file(dir, "codec.json", (uint8_t *)js, sizeof js - 1);
	if (n < 0) {
		return -1;
	}
	js[n] = 0;
	long run = json_int(js, "run"), tab = json_int(js, "tables_ram");
	const char *ents = strstr(js, "\"entries\"");
	if (run <= 0 || tab <= 0 || !ents) {
		snprintf(err, sizeof err, "bad codec.json");
		return -1;
	}
	run_addr = (uint32_t)run;
	ent_decode = run_addr + (uint32_t)json_int(ents, "decode");
	ent_encode = run_addr + (uint32_t)json_int(ents, "encode");
	ent_dec_init = run_addr + (uint32_t)json_int(ents, "dec_init");
	ent_dec_set = run_addr + (uint32_t)json_int(ents, "dec_set");
	ent_enc_init = run_addr + (uint32_t)json_int(ents, "enc_init");
	ent_enc_set = run_addr + (uint32_t)json_int(ents, "enc_set");
	ent_fec_init = run_addr + (uint32_t)json_int(ents, "fec_init");
	if (read_file(dir, "code.bin", csky_ram + run_addr, (long)(E_ADDR - run_addr)) <= 0) {
		return -1;
	}
	if ((uint32_t)tab < MODEM_BASE || (uint32_t)tab - MODEM_BASE >= MODEM_SIZE ||
	    read_file(dir, "tables.bin", csky_modem + ((uint32_t)tab - MODEM_BASE),
		      (long)(MODEM_SIZE - ((uint32_t)tab - MODEM_BASE))) <= 0) {
		return -1;
	}
	loaded = 1;
	enc_ready = dec_ready = 0;
	return 0;
}

/* call fn(args...) with the C-SKY V2 ABI: r0-r3, the rest on the stack */
static int call(uint32_t fn, int nargs, const uint32_t *args)
{
	static cpu_t cpu;
	memset(&cpu, 0, sizeof cpu);
	uint32_t sp = STACK_TOP;
	if (nargs > 4) {
		sp -= 4u * (uint32_t)(nargs - 4);
		for (int i = 4; i < nargs; i++) {
			STW(sp + 4u * (uint32_t)(i - 4), args[i]);
		}
	}
	for (int i = 0; i < nargs && i < 4; i++) {
		cpu.r[i] = args[i];
	}
	cpu.r[14] = sp;
	cpu.r[15] = RET_MAGIC;
	cpu.budget = BUDGET;
	int rc = codec_run(&cpu, fn);
	if (rc == -1) {
		snprintf(err, sizeof err, "codec jumped to 0x%08x, not a known code address", cpu.pc);
	} else if (rc == -2) {
		snprintf(err, sizeof err, "codec call to 0x%08x did not return (stopped at 0x%08x)", fn, cpu.pc);
	}
	return rc;
}

static void h16(uint32_t blk, uint32_t off, int16_t v) { STH(blk + off, (uint16_t)v); }
static int16_t g16(uint32_t blk, uint32_t off) { return (int16_t)LDH(blk + off); }

static int enc_start(void)
{
	static const struct { uint16_t off; int16_t v; } p[] = {
		{ 0x172C, 0x1840 }, { 0x173A, 0x2000 }, { 0x173C, 128 }, { 0x173E, -20 }, { 0x1740, -22 },
		{ 0x1742, 20 }, { 0x1744, -10 }, { 0x1746, -40 }, { 0x1748, 0x4000 }, { 0x174A, 3276 },
		{ 0x174C, 3276 }, { 0x174E, 1310 }, { 0x1750, 10 }, { 0x1752, 20 },
	};
	memset(csky_ram + E_ADDR, 0, STATE_BYTES);
	memset(csky_ram + EBITS_ADDR, 0, 0x100);
	for (unsigned i = 0; i < sizeof p / sizeof p[0]; i++) {
		h16(E_ADDR, p[i].off, p[i].v);
	}
	uint32_t a1[] = { E_ADDR, 1, 1 };
	uint32_t a2[] = { E_ADDR + 0x16E0, 1 };
	if (call(ent_enc_init, 3, a1) || call(ent_fec_init, 2, a2)) {
		return -1;
	}
	uint32_t a3[] = { E_ADDR, (uint32_t)(int32_t)g16(E_ADDR, 0x173C), (uint32_t)(int32_t)g16(E_ADDR, 0x173E) };
	if (call(ent_enc_set, 3, a3)) {
		return -1;
	}
	enc_ready = 1;
	return 0;
}

static int dec_start(void)
{
	memset(csky_ram + D_ADDR, 0, STATE_BYTES);
	memset(csky_ram + DBITS_ADDR, 0, 0x100);
	h16(D_ADDR, 0x1152, 0);
	h16(D_ADDR, 0x116A, 128);
	h16(D_ADDR, 0x116C, -20);
	uint32_t a1[] = { D_ADDR, 1 };
	uint32_t a2[] = { D_ADDR + 0xFD0, 1 };
	uint32_t a3[] = { D_ADDR + 0x12AE, HALF, D_ADDR + 0x1354, 0, 8, 0, D_ADDR };
	if (call(ent_dec_init, 2, a1) || call(ent_fec_init, 2, a2) || call(ent_decode, 7, a3)) {
		return -1;
	}
	uint32_t a4[] = { D_ADDR, (uint32_t)(int32_t)g16(D_ADDR, 0x116A), (uint32_t)(int32_t)g16(D_ADDR, 0x116C) };
	if (call(ent_dec_set, 3, a4)) {
		return -1;
	}
	dec_ready = 1;
	return 0;
}

void ambe_set_flags(uint32_t flags) { enc_flags = flags; }
void ambe_reset(void) { enc_ready = dec_ready = 0; }

int ambe_encode(const int16_t pcm[AMBE_FRAME_SAMPLES], uint8_t bits[AMBE_BITS])
{
	memset(bits, 0, AMBE_BITS);
	if (!loaded) {
		snprintf(err, sizeof err, "codec not loaded");
		return -1;
	}
	if (setjmp(fault_jmp)) {
		enc_ready = 0;
		return -1;
	}
	if (!enc_ready && enc_start()) {
		return -1;
	}
	memcpy(csky_ram + EPCM_ADDR, pcm, AMBE_FRAME_SAMPLES * 2);
	for (uint32_t h = 0; h < 2; h++) {
		uint32_t a[] = { EBITS_ADDR, (uint32_t)(int32_t)g16(E_ADDR, 0x1736), EPCM_ADDR + h * HALF * 2, HALF,
				 enc_flags, h, (uint32_t)(int32_t)g16(E_ADDR, 0x173A), E_ADDR };
		if (call(ent_encode, 8, a)) {
			enc_ready = 0;
			return -1;
		}
	}
	for (int i = 0; i < AMBE_BITS; i++) {
		bits[i] = (uint8_t)(LDH(EBITS_ADDR + 2u * (uint32_t)i) & 1);
	}
	return 0;
}

int ambe_decode(const uint8_t bits[AMBE_BITS], int16_t pcm[AMBE_FRAME_SAMPLES])
{
	memset(pcm, 0, AMBE_FRAME_SAMPLES * 2);
	if (!loaded) {
		snprintf(err, sizeof err, "codec not loaded");
		return -1;
	}
	if (setjmp(fault_jmp)) {
		dec_ready = 0;
		return -1;
	}
	if (!dec_ready && dec_start()) {
		return -1;
	}
	for (int i = 0; i < AMBE_BITS; i++) {
		STH(DBITS_ADDR + 2u * (uint32_t)i, bits[i] & 1);
	}
	for (uint32_t h = 0; h < 2; h++) {
		uint32_t a[] = { DPCM_ADDR + h * HALF * 2, HALF, DBITS_ADDR, (uint32_t)(int32_t)g16(D_ADDR, 0x1166), 0, h,
				 D_ADDR };
		if (call(ent_decode, 7, a)) {
			dec_ready = 0;
			return -1;
		}
	}
	memcpy(pcm, csky_ram + DPCM_ADDR, AMBE_FRAME_SAMPLES * 2);
	return 0;
}
