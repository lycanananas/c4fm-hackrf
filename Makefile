# SPDX-License-Identifier: MIT
# make codec STOCK=<your DM-32UV stock .bin or flash dump>   carve the codec into codec/ (once)
# make                                                       translate it; build build/ambe, build/libambe.so, build/ysftx
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -fPIC
GENFLAGS = -O1 -fPIC -w
B = build

RF = third_party/radiofoundry
YSF_SRC = $(wildcard $(RF)/core/ysf/*.c) $(RF)/core/fec/conv.c $(RF)/core/fec/crc16.c $(RF)/core/fec/golay.c \
	$(RF)/core/dmr/ambe/ambeFec.c

all: $(B)/ambe $(B)/libambe.so $(B)/ysftx

codec:
	@test -n "$(STOCK)" || { echo "usage: make codec STOCK=path/to/stock.bin"; exit 1; }
	python3 tools/extract_codec.py $(STOCK)

$(B)/codec_gen.c: codec/code.bin codec/codec.json tools/gen_codec_c.py
	python3 tools/gen_codec_c.py

$(B)/codec_gen.o: $(B)/codec_gen.c src/cskyrt.h
	$(CC) $(GENFLAGS) -Isrc -c $< -o $@

$(B)/ambe.o: src/ambe.c src/ambe.h src/cskyrt.h
	@mkdir -p $(B)
	$(CC) $(CFLAGS) -Isrc -c $< -o $@

$(B)/libambe.so: $(B)/ambe.o $(B)/codec_gen.o
	$(CC) -shared -o $@ $^

$(B)/ambe: src/ambe_cli.c $(B)/ambe.o $(B)/codec_gen.o
	$(CC) $(CFLAGS) -Isrc -o $@ $^

$(B)/ysftx: src/ysftx.c $(B)/ambe.o $(B)/codec_gen.o $(YSF_SRC)
	$(CC) -O2 -g -Isrc -I$(RF)/core -o $@ $^

clean:
	rm -rf $(B)

.PHONY: all codec clean
