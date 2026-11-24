/* SPDX-License-Identifier: MIT */
/* ambe: encode/decode raw audio with the emulated codec.
 *   ambe enc  < in.s16 > out.ambe     8 kHz mono s16le in, 7 bytes per 20 ms frame out (49 bits, MSB first)
 *   ambe dec  < in.ambe > out.s16
 *   ambe loop < in.s16 > out.s16      encode then decode
 *   ambe bench                        frames per second for both directions
 * Options before the command: -c DIR (codec directory, default codec/), -f FLAGS (encoder flags, default 0x1840). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ambe.h"

static void pack(const uint8_t *b, uint8_t out[7])
{
	memset(out, 0, 7);
	for (int i = 0; i < AMBE_BITS; i++) {
		out[i / 8] |= (uint8_t)((b[i] & 1) << (7 - i % 8));
	}
}

static void unpack(const uint8_t in[7], uint8_t *b)
{
	for (int i = 0; i < AMBE_BITS; i++) {
		b[i] = (in[i / 8] >> (7 - i % 8)) & 1;
	}
}

static int die(void)
{
	fprintf(stderr, "ambe: %s\n", ambe_error());
	return 1;
}

int main(int argc, char **argv)
{
	const char *dir = "codec";
	int i = 1;
	for (; i < argc && argv[i][0] == '-'; i++) {
		if (!strcmp(argv[i], "-c") && i + 1 < argc) {
			dir = argv[++i];
		} else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
			ambe_set_flags((uint32_t)strtoul(argv[++i], NULL, 0));
		} else {
			break;
		}
	}
	if (i >= argc) {
		fprintf(stderr, "usage: ambe [-c dir] [-f flags] enc|dec|loop|bench\n");
		return 2;
	}
	const char *cmd = argv[i];
	if (ambe_load(dir)) {
		return die();
	}
	int16_t pcm[AMBE_FRAME_SAMPLES];
	uint8_t bits[AMBE_BITS], pk[7];
	if (!strcmp(cmd, "enc")) {
		while (fread(pcm, 2, AMBE_FRAME_SAMPLES, stdin) == AMBE_FRAME_SAMPLES) {
			if (ambe_encode(pcm, bits)) return die();
			pack(bits, pk);
			fwrite(pk, 1, 7, stdout);
		}
	} else if (!strcmp(cmd, "dec")) {
		while (fread(pk, 1, 7, stdin) == 7) {
			unpack(pk, bits);
			if (ambe_decode(bits, pcm)) return die();
			fwrite(pcm, 2, AMBE_FRAME_SAMPLES, stdout);
		}
	} else if (!strcmp(cmd, "loop")) {
		while (fread(pcm, 2, AMBE_FRAME_SAMPLES, stdin) == AMBE_FRAME_SAMPLES) {
			if (ambe_encode(pcm, bits) || ambe_decode(bits, pcm)) return die();
			fwrite(pcm, 2, AMBE_FRAME_SAMPLES, stdout);
		}
	} else if (!strcmp(cmd, "bench")) {
		for (int k = 0; k < AMBE_FRAME_SAMPLES; k++) {
			pcm[k] = (int16_t)((k * 997) % 8000 - 4000);
		}
		clock_t t0 = clock();
		int n = 500;
		for (int k = 0; k < n; k++) {
			if (ambe_encode(pcm, bits) || ambe_decode(bits, pcm)) return die();
		}
		double s = (double)(clock() - t0) / CLOCKS_PER_SEC;
		fprintf(stderr, "%d frames enc+dec in %.2f s: %.1fx real time\n", n, s, n * 0.02 / s);
	} else {
		fprintf(stderr, "ambe: unknown command %s\n", cmd);
		return 2;
	}
	return 0;
}
