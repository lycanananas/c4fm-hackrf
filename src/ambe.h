/* SPDX-License-Identifier: MIT */
/* AMBE+2 (DMR / YSF DN half rate) through the emulated DM-32UV codec. One encoder and one decoder, usable together. */
#ifndef AMBE_H
#define AMBE_H

#include <stdint.h>

#define AMBE_FRAME_SAMPLES	160	/* 20 ms at 8 kHz */
#define AMBE_BITS		49	/* one bit per byte, in the codec's own order (as RadioFoundry's vocoder HAL) */

#define AMBE_ENC_PLAIN		0x0800u	/* encode flags (RadioFoundry ambe2_flags.h): plain */
#define AMBE_ENC_NR		0x0040u	/* + noise reduction */
#define AMBE_ENC_TONES		0x1000u	/* + tone frames */
#define AMBE_ENC_AGC		0x2000u	/* + AGC */
#define AMBE_ENC_DEFAULT	0x1840u

/* Load codec/code.bin, codec/tables.bin and codec/codec.json from dir. Returns 0, or -1 with a message on stderr. */
int ambe_load(const char *dir);
void ambe_set_flags(uint32_t flags);
void ambe_reset(void);	/* start a new transmission on both sides */
int ambe_encode(const int16_t pcm[AMBE_FRAME_SAMPLES], uint8_t bits[AMBE_BITS]);
int ambe_decode(const uint8_t bits[AMBE_BITS], int16_t pcm[AMBE_FRAME_SAMPLES]);
const char *ambe_error(void);

#endif
