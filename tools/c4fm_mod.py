#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""c4fm_mod: C4FM symbols (int8 +3/+1/-1/-3, 4800/s, from ysftx) -> HackRF I/Q (signed 8-bit, "cs8").

    c4fm_mod.py in.sym out.cs8 [--rate 2400000] [--offset 100000] [--dev 2700]

YSF modulation (RadioFoundry docs/spec/ysf.md): root raised cosine pulse, roll-off 0.2, outer deviation 2700 Hz
(inner 900 Hz). The signal sits --offset Hz above the HackRF centre so the LO leakage stays off it: tune the HackRF to
(channel - offset). out.cs8 may be "-" for stdout (hackrf_transfer -t /dev/stdin).
"""
import argparse
import sys

import numpy as np

SYM_RATE = 4800
FS1 = 48000
SPS = FS1 // SYM_RATE


def rrc(alpha, sps, span):
    t = np.arange(-span * sps // 2, span * sps // 2 + 1) / sps
    h = np.zeros_like(t)
    for i, x in enumerate(t):
        if abs(x) < 1e-9:
            h[i] = 1 - alpha + 4 * alpha / np.pi
        elif abs(abs(x) - 1 / (4 * alpha)) < 1e-9:
            h[i] = alpha / np.sqrt(2) * ((1 + 2 / np.pi) * np.sin(np.pi / (4 * alpha))
                                         + (1 - 2 / np.pi) * np.cos(np.pi / (4 * alpha)))
        else:
            h[i] = (np.sin(np.pi * x * (1 - alpha)) + 4 * alpha * x * np.cos(np.pi * x * (1 + alpha))) / \
                   (np.pi * x * (1 - (4 * alpha * x) ** 2))
    return h / h.sum()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("sym")
    ap.add_argument("out")
    ap.add_argument("--rate", type=int, default=2400000, help="I/Q sample rate (a multiple of 48000)")
    ap.add_argument("--offset", type=float, default=100000.0, help="signal offset from the centre, Hz")
    ap.add_argument("--dev", type=float, default=2700.0, help="outer (+-3) deviation, Hz")
    ap.add_argument("--amp", type=float, default=0.7, help="I/Q amplitude, 0..1 of full scale")
    ap.add_argument("--lead", type=float, default=0.05, help="unmodulated carrier before and after, s")
    a = ap.parse_args()
    if a.rate % FS1:
        sys.exit("c4fm_mod: --rate must be a multiple of 48000")
    up = a.rate // FS1

    syms = np.fromfile(a.sym, dtype=np.int8).astype(np.float64)
    if not len(syms):
        sys.exit("c4fm_mod: no symbols")
    imp = np.zeros(len(syms) * SPS)
    imp[::SPS] = syms * SPS
    h = rrc(0.2, SPS, 8)
    f1 = np.convolve(imp, h)  # frequency in symbol levels, at 48 kHz
    lead = np.zeros(int(a.lead * FS1))
    f1 = np.concatenate([lead, f1, lead]) * (a.dev / 3.0)

    out = sys.stdout.buffer if a.out == "-" else open(a.out, "wb")
    phase = 0.0
    chunk = FS1  # one second at a time
    xs = np.arange(up) / up
    for s in range(0, len(f1), chunk):
        seg = f1[s:s + chunk + 1]
        if len(seg) < 2:
            break
        n = len(seg) - 1
        # linear interpolation 48 kHz -> rate
        fi = (seg[:-1, None] * (1 - xs) + seg[1:, None] * xs).reshape(-1)
        inst = 2 * np.pi * (fi + a.offset) / a.rate
        ph = phase + np.cumsum(inst)
        phase = float(ph[-1] % (2 * np.pi))
        iq = np.empty(2 * len(ph), dtype=np.int8)
        iq[0::2] = np.round(np.cos(ph) * 127 * a.amp).astype(np.int8)
        iq[1::2] = np.round(np.sin(ph) * 127 * a.amp).astype(np.int8)
        out.write(iq.tobytes())
        del n
    out.flush()
    sys.stderr.write("c4fm_mod: %d symbols, %.1f s at %d S/s, offset %+.0f Hz\n"
                     % (len(syms), len(f1) / FS1, a.rate, a.offset))


if __name__ == "__main__":
    main()
