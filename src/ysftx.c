/* SPDX-License-Identifier: MIT */
/* ysftx: 8 kHz mono s16le audio on stdin -> a YSF DN call as C4FM symbols on stdout (one int8 per symbol:
 * +3 +1 -1 -3, 4800 per second). Preamble, header, VD mode 2 frames, terminator: RadioFoundry's core/ysf call
 * builder; the voice is AMBE+2 from the emulated DM-32UV codec.
 *   ysftx [-c codecdir] [-s CALLSIGN] [-i RADIOID] [-g DGID] [-f encflags] < in.s16 > out.sym */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ambe.h"
#include "ysf/ysf.h"
#include "ysf/ysf_id.h"
#include "air/air_syms.h"

static ysf_call_tx_t tx;

static void drain(void)
{
	uint16_t first, n;
	while ((n = ysf_call_tx_ready(&tx, &first)) > 0) {
		const uint8_t *p = ysf_call_tx_syms(&tx);
		int8_t out[YSF_FRAME_SYMS];
		for (uint16_t i = 0; i < n; i++) {
			out[i] = air_sym_level(air_sym_get(p, (uint16_t)(first + i)));
		}
		fwrite(out, 1, n, stdout);
		ysf_call_tx_sent(&tx, n);
	}
}

static int voice(const int16_t *pcm)
{
	uint8_t bits[AMBE_BITS], v[YSF_VOICE_BYTES];
	if (ambe_encode(pcm, bits)) {
		fprintf(stderr, "ysftx: %s\n", ambe_error());
		return -1;
	}
	ambeFecEncode(bits, v);
	while (!ysf_call_tx_voice(&tx, v)) {
		drain();	/* the frame in hand is full: send it, the next one takes the voice */
		if (ysf_call_tx_done(&tx)) {
			return -1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *dir = "codec";
	ysf_tx_id_t id;
	memset(&id, 0, sizeof id);
	strcpy(id.callsign, "N0CALL");
	id.mr = YSF_MR_DIRECT;
	const char *rid = NULL;
	for (int i = 1; i < argc; i++) {
		if (i + 1 >= argc) {
			fprintf(stderr, "usage: ysftx [-c dir] [-s callsign] [-i radioid] [-g dgid] [-f flags]\n");
			return 2;
		}
		if (!strcmp(argv[i], "-c")) dir = argv[++i];
		else if (!strcmp(argv[i], "-s")) snprintf(id.callsign, sizeof id.callsign, "%s", argv[++i]);
		else if (!strcmp(argv[i], "-i")) rid = argv[++i];
		else if (!strcmp(argv[i], "-g")) id.dgid = (uint8_t)atoi(argv[++i]);
		else if (!strcmp(argv[i], "-f")) ambe_set_flags((uint32_t)strtoul(argv[++i], NULL, 0));
		else { fprintf(stderr, "ysftx: unknown option %s\n", argv[i]); return 2; }
	}
	if (rid) {
		snprintf(id.radio_id, sizeof id.radio_id, "%s", rid);
	} else {
		ysf_rid_fallback(0, id.callsign, id.radio_id);
	}
	if (ambe_load(dir)) {
		fprintf(stderr, "ysftx: %s\n", ambe_error());
		return 1;
	}
	fprintf(stderr, "ysftx: %s, radio ID %s, DG-ID %u\n", id.callsign, id.radio_id, id.dgid);

	ysf_call_tx_begin(&tx, &id);
	int16_t pcm[AMBE_FRAME_SAMPLES];
	long frames = 0;
	while (fread(pcm, 2, AMBE_FRAME_SAMPLES, stdin) == AMBE_FRAME_SAMPLES) {
		if (voice(pcm)) return 1;
		drain();
		frames++;
	}
	/* end: pad the frame in hand with silence, then the terminator */
	int16_t sil[AMBE_FRAME_SAMPLES] = { 0 };
	uint8_t bits[AMBE_BITS], v[YSF_VOICE_BYTES];
	ambe_encode(sil, bits);
	ambeFecEncode(bits, v);
	ysf_call_tx_end(&tx, v);
	while (!ysf_call_tx_done(&tx)) {
		drain();
		uint16_t first;
		if (!ysf_call_tx_ready(&tx, &first) && !ysf_call_tx_done(&tx)) {
			break;
		}
	}
	drain();
	fprintf(stderr, "ysftx: %ld voice frames (%.1f s)\n", frames, frames * 0.02);
	return 0;
}
