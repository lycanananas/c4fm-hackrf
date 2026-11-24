/* SPDX-License-Identifier: MIT */
/* Runtime for the statically translated C-SKY V2 codec: registers, the flat memory map, helpers. */
#ifndef CSKYRT_H
#define CSKYRT_H

#include <stdint.h>
#include <string.h>

#define RAM_SIZE	0x100000u	/* 0x00000000.. : the codec code at its run address, state blocks, stack */
#define MODEM_BASE	0x18000000u	/* the modem SRAM window that holds the codec tables */
#define MODEM_SIZE	0x10000u
#define RET_MAGIC	0xFFFFFFF0u	/* r15 on entry: returning here ends the call */

typedef struct {
	uint32_t r[32];
	uint32_t c;		/* the condition / carry bit */
	int64_t acc;		/* DSP {HI, LO} */
	int64_t low;		/* LO widened, for the saturating mflos */
	uint64_t budget;	/* dispatches left before a call is cut off (a runaway guard) */
	uint32_t pc;		/* where a failed call stopped */
} cpu_t;

extern uint8_t csky_ram[RAM_SIZE];
extern uint8_t csky_modem[MODEM_SIZE];
void csky_fault(uint32_t addr, const char *what);

static inline uint8_t *csky_p(uint32_t a, uint32_t n)
{
	if (a < RAM_SIZE && a + n <= RAM_SIZE) {
		return csky_ram + a;
	}
	if (a - MODEM_BASE < MODEM_SIZE && a - MODEM_BASE + n <= MODEM_SIZE) {
		return csky_modem + (a - MODEM_BASE);
	}
	csky_fault(a, "memory access outside the map");
	return csky_ram;
}

static inline uint32_t LDW(uint32_t a) { uint32_t v; memcpy(&v, csky_p(a, 4), 4); return v; }
static inline uint32_t LDH(uint32_t a) { uint16_t v; memcpy(&v, csky_p(a, 2), 2); return v; }
static inline uint32_t LDB(uint32_t a) { return *csky_p(a, 1); }
static inline void STW(uint32_t a, uint32_t v) { memcpy(csky_p(a, 4), &v, 4); }
static inline void STH(uint32_t a, uint32_t v) { uint16_t h = (uint16_t)v; memcpy(csky_p(a, 2), &h, 2); }
static inline void STB(uint32_t a, uint32_t v) { *csky_p(a, 1) = (uint8_t)v; }

static inline uint32_t SHL(uint32_t x, uint32_t n) { n &= 63; return n > 31 ? 0 : x << n; }
static inline uint32_t SHR(uint32_t x, uint32_t n) { n &= 63; return n > 31 ? 0 : x >> n; }
static inline uint32_t SAR(uint32_t x, uint32_t n) { n &= 63; return (uint32_t)((int32_t)x >> (n > 31 ? 31 : n)); }
static inline uint32_t CLZ(uint32_t x) { return x ? (uint32_t)__builtin_clz(x) : 32; }
static inline uint32_t DIVS(uint32_t a, uint32_t b)
{
	if (b == 0) return 0;
	if ((int32_t)a == INT32_MIN && (int32_t)b == -1) return a;
	return (uint32_t)((int32_t)a / (int32_t)b);
}
static inline uint32_t DIVU(uint32_t a, uint32_t b) { return b ? a / b : 0; }
static inline uint32_t SAT32(int64_t v)
{
	return (uint32_t)(v > INT32_MAX ? INT32_MAX : v < INT32_MIN ? INT32_MIN : (int32_t)v);
}

#define SETLO(v)	(ACC = (int64_t)(((uint64_t)ACC & 0xFFFFFFFF00000000ull) | (uint32_t)(v)))
#define TRAP(a, s)	do { cpu->pc = (a); csky_fault((a), "untranslated instruction: " s); } while (0)

int codec_run(cpu_t *cpu, uint32_t pc);

#endif
