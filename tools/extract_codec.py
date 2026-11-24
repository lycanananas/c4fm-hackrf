#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Carve the DM-32UV AMBE+2 codec out of YOUR stock firmware file or program flash dump.

The codec belongs to DVSI/Baofeng. It is never stored in this repository: this tool reads your own file and writes
the code, the table window and a small JSON description into codec/ (ignored by git).

tools/codec_profiles.py (from RadioFoundry, MIT) recognizes the file by SHA-256 and finds the windows: every DM-32UV
build RadioFoundry knows, as a stock .bin file or a 1 MB program flash read.
"""
import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("stock", help="DM-32UV stock firmware (.bin) or a program flash dump")
    ap.add_argument("-o", "--out", default=os.path.join(ROOT, "codec"), help="output directory (default: codec/)")
    a = ap.parse_args()

    sys.path.insert(0, HERE)
    import codec_profiles as hc  # noqa: E402

    stock = open(a.stock, "rb").read()
    try:
        prof, code, tables = hc.extract(stock, board="dm32")
    except hc.ExtractError as e:
        sys.exit("extract_codec: %s" % e)
    os.makedirs(a.out, exist_ok=True)
    open(os.path.join(a.out, "code.bin"), "wb").write(code)
    open(os.path.join(a.out, "tables.bin"), "wb").write(tables)
    desc = {
        "name": prof["name"], "tag": prof["tag"],
        "run": prof["code"][2], "code_len": len(code),
        "tables_ram": prof["tables"][2], "tables_len": len(tables),
        "entries": prof["entries"],
        "code_sha256": hashlib.sha256(code).hexdigest(),
    }
    json.dump(desc, open(os.path.join(a.out, "codec.json"), "w"), indent=1)
    print("codec %s (build %d): code 0x%X bytes at 0x%X, tables 0x%X bytes at 0x%X -> %s"
          % (desc["name"], desc["tag"], len(code), desc["run"], len(tables), desc["tables_ram"], a.out))


if __name__ == "__main__":
    main()
