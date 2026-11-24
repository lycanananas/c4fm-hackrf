# c4fm-hackrf

A Yaesu System Fusion (C4FM, DN mode) transceiver for the HackRF, with the AMBE+2 vocoder taken from
**your own** Baofeng DM-32UV firmware and run in a C-SKY emulator on the PC.

Status: TX works on air (a DM-32UV running RadioFoundry received it, callsign and audio). RX on the HackRF and live
microphone input are not written yet.

```
audio (8 kHz) -> [emulated DM-32UV codec] -> AMBE+2 -> [YSF DN frames] -> C4FM symbols -> FM I/Q -> HackRF
```

## The codec

The AMBE+2 codec belongs to DVSI and Baofeng, so it is never part of this repository. You carve it out of your own DM-32UV
stock firmware file or program flash dump. `tools/gen_codec_c.py` then statically translates its C-SKY V2 machine code
(CK803 with DSP) into C, using the C-SKY binutils `objdump`. The generated `build/codec_gen.c` is derived from the codec,
so it stays local as well.

```sh
make codec STOCK=path/to/DM32.01.01.049.bin   # or a 1 MB program flash dump; needs a RadioFoundry checkout in ../RadioFoundry
make                                          # needs ~/toolchains/csky-elf (or CSKY_BIN=...)
build/ambe loop < in.s16 > out.s16            # 8 kHz mono s16le
build/ambe enc < in.s16 > out.ambe            # 7 bytes (49 bits) per 20 ms frame
build/ambe dec < in.ambe > out.s16
```

## Transmit

```sh
sox speech.wav -r 8000 -c 1 -b 16 -e signed speech.s16 gain -n -3
build/ysftx -s N0CALL < speech.s16 > call.sym       # -i RADIOID, -g DGID; preamble, header, VD2 frames, terminator
python3 tools/c4fm_mod.py call.sym call.cs8         # RRC 0.2, +-2700/900 Hz, 2.4 MS/s, signal 100 kHz above centre
hackrf_transfer -t call.cs8 -f 434900000 -s 2400000 -a 0 -x 10    # on air at 435.000 MHz
```

You need an amateur radio licence to transmit, and the bands' rules apply. AMBE+2 is a speech codec: music turns into noise.

## Library

`build/libambe.so` exposes `ambe_load`, `ambe_encode` and `ambe_decode` (`src/ambe.h`). The 49 bits are in the
codec's own order, which is the order RadioFoundry's DMR and YSF code uses.

## Licence

MIT, for the code in this repository. `third_party/radiofoundry/` is a copy of the YSF and FEC code from
[RadioFoundry](https://github.com/RadioFoundry/RadioFoundry) (MIT, see its LICENSE and VERSION). The codec, and anything generated from it, is not covered by this licence.
