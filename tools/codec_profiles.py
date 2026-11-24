# SPDX-License-Identifier: MIT
# Copyright (c) 2026 The RadioFoundry Authors
"""Which stock firmware files carry the HR_C7000 radios' AMBE+2 codec, and where: recognize a stock file or a program
flash dump by SHA-256 and carve the code and table windows.

Copied from RadioFoundry tools/hrc7000_codec.py (MIT, commit 454a5b76be4f; see third_party/radiofoundry/LICENSE): the
profiles and extract(), without the image merge and the board registry. Only hashes, addresses and sizes: no codec
bytes.
"""
import hashlib
import struct
import zlib

APP_BASE = 0x0300C000
STOCK_HEADER = 0x100
MAGIC = b"BFUV32-V2"
CODEC_SIG = (0x152514D8, 0x74C776CD)
PROGMEM_BASE = 0x03000000   # a program flash dump starts here

# Entry points, offsets from the codec start (codec-dm32.md "Entry points"); fec_init differs per version
ENTRIES = ("decode", "encode", "dec_init", "dec_set", "enc_init", "enc_set", "fec_init")

# The 049 entry points: every DM-32UV stock build from 032 to 049, and NRFB 050, carries the same codec code, byte for
# byte, except for its table pointers (the NRF and fanti builds' tables sit 8 bytes higher, NRFB's 0x18 higher) and
# stock code that lies inside the window but isn't codec (codec-dm32.md "Stock versions")
ENTRIES_049 = {"decode": 0x0, "encode": 0x260, "dec_init": 0xB4, "dec_set": 0x84, "enc_init": 0x314,
               "enc_set": 0x2E4, "fec_init": 0x1BF8}

PROFILES = {
    "03107b6f600e7fa95105af8324cff349c0f17fe30db249c14d11e79baa8da97a": {
        "name": "DM32.01.01.049.bin", "board": "dm32", "tag": 49, "size": 869688,
        "code": (0x030C687C, 0x14600, 0x00016CDC),       # flash address, length, run address
        "tables": (0x03072628, 0x2F78, 0x18000EA8),
        "code_sha256": "355ca9061979eceb2991826da9d39c95b4a9d40466245923d541a6556ceeafd1",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": {"decode": 0x0, "encode": 0x260, "dec_init": 0xB4, "dec_set": 0x84, "enc_init": 0x314,
                    "enc_set": 0x2E4, "fec_init": 0x1BF8},
    },
    "f8484c13c994e920649d7b7bc2b98a98a76cfd0836865e5995a00627fc0c2887": {
        "name": "DM32.00.01.046HRVocoder.bin", "board": "dm32", "tag": 46, "size": 890516,
        "code": (0x030CB13C, 0x140DC, 0x0001B838),
        "tables": (0x030723A8, 0x2F78, 0x18000E48),
        "code_sha256": "02743cf4b3d252b8764fe083fb808b00ab42f0f0ab76935e62ca59fd5c5e64fb",
        "tables_sha256": "cd5a4d270f555cdbd586bca8de89e4e845789ed7aa2a2bb7414b6c3a270ef803",
        "entries": {"decode": 0x0, "encode": 0x260, "dec_init": 0xB4, "dec_set": 0x84, "enc_init": 0x314,
                    "enc_set": 0x2E4, "fec_init": 0x1DCC},
    },
    "5ee2cb549792d5596fa50bb826613cde212e38f58b10b0084fdfd7b6032ec44d": {
        "name": "DM32.01.01.032.bin", "board": "dm32", "tag": 32, "size": 872708,
        "code": (0x030C74B4, 0x14600, 0x00016CDC),
        "tables": (0x03071908, 0x2F78, 0x18000EA8),
        "code_sha256": "cc17ee0bf3ee45d16912e44351a3434fc1ebcbc6e22ef3e42463e394624bb164",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "249bcd25a021bb5e384633232c3a2da5fb5cf0881d08fc4ab573faaf3a1fb28a": {
        "name": "DM32.01.01.037.bin", "board": "dm32", "tag": 37, "size": 867280,
        "code": (0x030C5F08, 0x14600, 0x00016CDC),
        "tables": (0x03071D68, 0x2F78, 0x18000EA8),
        "code_sha256": "6b1c46cb4bfefbbe9fe5d2d47d43624a4854fa4d52d5db29b75a5c968d68a065",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "101dd348b11b21ba67274d40e1b2cc8248863e442c7da0471bc9f7db09f61f6b": {
        "name": "DM32.01.01.039.bin", "board": "dm32", "tag": 39, "size": 868572,
        "code": (0x030C6414, 0x14600, 0x00016CDC),
        "tables": (0x03072228, 0x2F78, 0x18000EA8),
        "code_sha256": "6b1c46cb4bfefbbe9fe5d2d47d43624a4854fa4d52d5db29b75a5c968d68a065",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "016962d82b926e489e729abee46b13f97d223f8e97e07fe3b8bcba1dd1e37058": {
        "name": "DM32.01.01.040.bin", "board": "dm32", "tag": 40, "size": 868588,
        "code": (0x030C6424, 0x14600, 0x00016CDC),
        "tables": (0x03072238, 0x2F78, 0x18000EA8),
        "code_sha256": "6b1c46cb4bfefbbe9fe5d2d47d43624a4854fa4d52d5db29b75a5c968d68a065",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "ab21bc8dedb225a3e48c72e07af029fd0c453f00018f3b83a062fd0b9a3e3049": {
        "name": "DM32.01.01.046.bin", "board": "dm32", "tag": 46, "size": 868984,
        "code": (0x030C65B0, 0x14600, 0x00016CDC),
        "tables": (0x03072378, 0x2F78, 0x18000EA8),
        "code_sha256": "9720ec0c923ac32bc909d06a0d4c414c6a1e80c3eaa6e9c5b5df0d0bf5ff5665",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "7c045763c5b98c85836e932d9b4612f2c97fe67f5a4893ff564ecff27cfe1005": {
        "name": "DM32.01.01.047.bin", "board": "dm32", "tag": 47, "size": 869748,
        "code": (0x030C68B8, 0x14600, 0x00016CDC),
        "tables": (0x03072658, 0x2F78, 0x18000EA8),
        "code_sha256": "355ca9061979eceb2991826da9d39c95b4a9d40466245923d541a6556ceeafd1",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    # 01.01.047 as a second build (the file is dated 20250425): 15 words in the code window that aren't codec differ from 049's
    "3e612db62507fc2901777ccc315fcbc4a0b9ca0a953c8f0cd34c39af4a39b4e4": {
        "name": "DM32_047_20250425.bin", "board": "dm32", "tag": 47, "size": 869368,
        "code": (0x030C673C, 0x14600, 0x00016CDC),
        "tables": (0x030724E8, 0x2F78, 0x18000EA8),
        "code_sha256": "cd44ff0ac0bb817b7fa1942021963697cba0d10266e6f17cf036dae16a23dbd8",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "fda860febfcf1a234eed7fa73272112891074aac83746e4f8dfe224a2a700f8f": {
        "name": "DM32.01.L01.048.bin", "board": "dm32", "tag": 48, "size": 860416,
        "code": (0x030C4444, 0x14600, 0x00016CDC),
        "tables": (0x03070468, 0x2F78, 0x18000EA8),
        "code_sha256": "cf275cd01ef8ba09c2873009ac5923dd5d2bc2384f6ceaa8b658b9d46d4478e2",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "1930cbe7c8ae173badff868f5e6f1f754f8601956965696d1de4ce48433cbc93": {
        "name": "DM32.01.02.046.bin", "board": "dm32", "tag": 46, "size": 868952,
        "code": (0x030C6590, 0x14600, 0x00016CDC),
        "tables": (0x03072358, 0x2F78, 0x18000EA8),
        "code_sha256": "9720ec0c923ac32bc909d06a0d4c414c6a1e80c3eaa6e9c5b5df0d0bf5ff5665",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "aff6b4dc09dcce45847173defba26e94157cc628af86826e21e5af227bdc52dd": {
        "name": "DM32.01.01.049 NRF build", "board": "dm32", "tag": 49, "size": 873964,
        "code": (0x030C7914, 0x14600, 0x00016CDC),
        "tables": (0x03072E80, 0x2F78, 0x18000EB0),
        "code_sha256": "cd0820a18df0b53bf011907a02d5b649bfbccf030c3d0432f4e363077d67a2c0",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    "a8a5fc80e7116e8e8c9926f9c5e6d56a72689d70e09db3f0fec57b3a01ec4a31": {
        "name": "DM32.01.01.049 fanti build", "board": "dm32", "tag": 49, "size": 874028,
        "code": (0x030C7954, 0x14600, 0x00016CDC),
        "tables": (0x03072EC0, 0x2F78, 0x18000EB0),
        "code_sha256": "cd0820a18df0b53bf011907a02d5b649bfbccf030c3d0432f4e363077d67a2c0",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    # DM32.NRFB.01.050, known only from a program flash read: the key is the code window's SHA-256. Its codec is the
    # 049 one (tables 10684c33...); the table pointers sit 0x10 above the NRF builds' and the tables end at 0x18003E38
    # (docs/spec/codec-dm32.md)
    "8d7f57eb84147dc6fc85d7ca4dd80fe6f2256cfb2cfe5b822bae07088a642db7": {
        "name": "DM32.NRFB.01.050 program flash", "board": "dm32", "kind": "progmem", "tag": 50,
        "size": 0x100000,
        "code": (0x030C72D8, 0x14600, 0x00016CDC),
        "tables": (0x03072810, 0x2F78, 0x18000EC0),
        "code_sha256": "8d7f57eb84147dc6fc85d7ca4dd80fe6f2256cfb2cfe5b822bae07088a642db7",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": ENTRIES_049,
    },
    # A whole program flash dump (1 MB from 0x03000000, e.g. stub/stubtool.py --progmem) holds the radio's own data
    # besides the firmware, so it's known by the SHA-256 of the code window (the key) and of the table window
    # (docs/spec/codec-dm1801pro.md 1)
    "8f7641b69a5cdfc946507ec48ddb67febe91d964520d5522bebd707f363f1a42": {
        "name": "DM-1801 Pro program flash (049 codec)", "board": "dm1801pro", "kind": "progmem", "tag": 49,
        "size": 0x100000,
        "code": (0x030A22F0, 0x14600, 0x00016CDC),
        "tables": (0x03068770, 0x2F78, 0x18000EF0),
        "code_sha256": "8f7641b69a5cdfc946507ec48ddb67febe91d964520d5522bebd707f363f1a42",
        "tables_sha256": "10684c33e3cc8238376e455fd96b1c15a863a864420dbbaa4589803c4eb0b0e1",
        "entries": {"decode": 0x0, "encode": 0x260, "dec_init": 0xB4, "dec_set": 0x84, "enc_init": 0x314,
                    "enc_set": 0x2E4, "fec_init": 0x1BF8},
    },
}

# DB25-D PRO stock images: plain, linked at 0x0300C000, no container (hardware-db25d.md 8). Code: 0x12B20 bytes at the
# signature, run at 0x1CEB0 (the stock start-up copies the RAM block from 0x030B4DA8-class addresses to 0x10000, which puts
# the codec at 0x1CEB0 in the three newest; the 2023-07-06 build's is at 0x1795C, its tables at 0x180010B4, the lowest). Tables: one 0x2D50 window (two object groups, 4 bytes apart) in the modem SRAM
# image, run at 0x180014AC + the build's shift. fec_init is +0x1DCC in all three
_DB25D_ENTRIES = {"decode": 0x0, "encode": 0x260, "dec_init": 0xB4, "dec_set": 0x84, "enc_init": 0x314,
                  "enc_set": 0x2E4, "fec_init": 0x1DCC}
PROFILES.update({
    "341536cbac0c1b2471f8198ebc456946e5fe026d96d153df14d6aa5566304f8b": {
        "name": "DB25-D PRO 909E.Dx.EARSAB.018_2025-01-21.bin", "board": "db25d", "tag": 2501, "size": 846700,
        "hdr": 0, "magic": None,
        "code_sha256": "c8152ea4f4eba93c5d83a6e30953c1872923aa67639399836906a5849db9e54e",
        "code": (0x030C1C58, 0x12B20, 0x0001CEB0),
        "tables": (0x0307A8EC, 0x2D50, 0x180014AC),
        "tables_sha256": "e1e435822471894c437048396f2ea96bea5803acc08446b8f1073714978e219e",
        "entries": _DB25D_ENTRIES,
    },
    "f2a4b214720b971b58cdadcc53d44695e1462b75296afc41f2a0b53a704d36b4": {
        "name": "DB25-D PRO 909E.Dx.EARSAB.018_2024-09-23.bin", "board": "db25d", "tag": 2409, "size": 845900,
        "hdr": 0, "magic": None,
        "code_sha256": "a2346ca4b122622476f437f9c031df70cace737b760bee614758cd5a4805b3cd",
        "code": (0x030C192C, 0x12B20, 0x0001CEB0),
        "tables": (0x0307A614, 0x2D50, 0x180014B4),
        "tables_sha256": "e1e435822471894c437048396f2ea96bea5803acc08446b8f1073714978e219e",
        "entries": _DB25D_ENTRIES,
    },
    "9e199f54cd6545d153d39542ca5be3ac1076ee215eb93ca630a83cbdbbff4606": {
        "name": "DB25-D 909E.D6x.EARSAB.018 2024-05-09 (db25d-v2024-05-09.bin)", "board": "db25d", "tag": 2405,
        "size": 843944, "hdr": 0, "magic": None,
        "code": (0x030C1130, 0x12B20, 0x0001CEB0),
        "tables": (0x0307A150, 0x2D50, 0x180014B0),
        "tables_sha256": "e1e435822471894c437048396f2ea96bea5803acc08446b8f1073714978e219e",
        "entries": _DB25D_ENTRIES,
    },
    "03f3ddfe1c4117ddf4ed64eaa1f72cd24783d5d0de8933ce53651e02b4fe2e68": {
        "name": "DB25-D_909E.Dx.EARSAB.018_2023-07-06.bin", "board": "db25d", "tag": 2307, "size": 808292,
        "hdr": 0, "magic": None,
        "code_sha256": "686a4173288dd6b3e43f61d8c9bd48f984dcfe8d56e013b3c7ef75a25881811a",
        "code": (0x030B79D4, 0x12B20, 0x0001795C),
        "tables": (0x030760E4, 0x2D50, 0x180010B4),
        "tables_sha256": "e1e435822471894c437048396f2ea96bea5803acc08446b8f1073714978e219e",
        "entries": _DB25D_ENTRIES,
    },
    # 020: a different compile of the same codec (other function order, run at 0x180B8, its own entry offsets; the tables
    # are byte for byte 018's, at 0x18001610). No vendor file is published, so it is known by its code window in a program
    # flash read, as the DM-1801 Pro's (hardware-db25d.md 8)
    "a9e67fb713b56c89b6571ee01b6d49fd605fb723ee2668d0b6afc09962bd8b90": {
        "name": "DB25-D PRO 909E.D6x.EARSAB.020 (program flash read)", "board": "db25d", "kind": "progmem", "tag": 20,
        "size": 0x100000,
        "code": (0x030C142C, 0x1315C, 0x000180B8),
        "tables": (0x0307E760, 0x2D50, 0x18001610),
        "code_sha256": "a9e67fb713b56c89b6571ee01b6d49fd605fb723ee2668d0b6afc09962bd8b90",
        "tables_sha256": "e1e435822471894c437048396f2ea96bea5803acc08446b8f1073714978e219e",
        "entries": {"decode": 0x0, "encode": 0x294, "dec_init": 0xE8, "dec_set": 0xA4, "enc_init": 0x400,
                    "enc_set": 0x32C, "fec_init": 0x1CE4},
    },
})
# Retevis RT10 V1.1.2: no vendor file, only a program flash read. 020's compile with one function inside the window
# 20 bytes shorter, so the codec code after it and fec_init sit 20 bytes lower; it runs from RAM at 0x16DD8 (the
# RAM block is at 0x10400). The tables are byte for byte 018's, at 0x1800420C (hardware-rt10.md 8)
PROFILES.update({
    "3f3b8740df14c81b44f53f984e4e570a609ec467233341729157f5c176cc3c15": {
        "name": "Retevis RT10 V1.1.2 (program flash read)", "board": "rt10", "kind": "progmem", "tag": 112,
        "size": 0x100000,
        "code": (0x0305E438, 0x12FFC, 0x00016DD8),
        "tables": (0x0303C76C, 0x2D50, 0x1800420C),
        "code_sha256": "3f3b8740df14c81b44f53f984e4e570a609ec467233341729157f5c176cc3c15",
        "tables_sha256": "e1e435822471894c437048396f2ea96bea5803acc08446b8f1073714978e219e",
        "entries": {"decode": 0x0, "encode": 0x294, "dec_init": 0xE8, "dec_set": 0xA4, "enc_init": 0x400,
                    "enc_set": 0x32C, "fec_init": 0x1CD0},
    },
})
# CRC-32 of the first 64 bytes of every table window above: a cheap first test when locate() looks for the tables in a
# program flash dump, before the SHA-256. Not a codec byte, only a fingerprint
TABLES_HEAD_CRC = 0x11475389
PROGMEM_SIZE = 0x100000
# A read of a whole 2 MB program flash (the RT10's backup) is searched in its first 1 MB
PROGMEM_SIZES = {PROGMEM_SIZE, 0x200000}


class ExtractError(Exception):
    pass


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def file_offset(addr, hdr=STOCK_HEADER):
    return addr - APP_BASE + hdr


def carve(stock, prof):
    """The code and table windows of a stock file, by the profile's kind."""
    windows = []
    for key in ("code", "tables"):
        addr, length, _ = prof[key]
        hdr = 0 if prof.get("kind") == "progmem" else prof.get("hdr", STOCK_HEADER)
        off = addr - PROGMEM_BASE if prof.get("kind") == "progmem" else file_offset(addr, hdr)
        if off < hdr or off + length > len(stock):
            raise ExtractError("%s window outside the file" % key)
        windows.append(stock[off:off + length])
    return windows


def locate(dump, profiles=None, board=None):
    """A known codec anywhere in a program flash dump (1 MB from 0x03000000, or a board's whole 2 MB). Each firmware version links the codec to its
    own flash addresses (DM-32 047 and 049 hold the same code, 0x3C bytes apart), so it is found by content: the code
    starts with the signature words and the tables by TABLES_HEAD_CRC, both 4-byte aligned, and each window must match
    a profile's SHA-256. Returns the profile with the addresses found (kind "progmem"), else None."""
    profiles = PROFILES if profiles is None else profiles
    profiles = [p for p in profiles.values() if board in (None, p["board"]) and "code_sha256" in p]
    if len(dump) not in PROGMEM_SIZES or not profiles:
        return None
    dump = dump[:PROGMEM_SIZE]
    sig = struct.pack("<2I", *CODEC_SIG)
    heads = None
    at = dump.find(sig)
    while at >= 0:
        # stock versions with the same codec bytes (037, 039, 040) are told apart by where they put it
        for p in sorted(profiles, key=lambda p: p["code"][0] != PROGMEM_BASE + at):
            clen, tlen = p["code"][1], p["tables"][1]
            if at % 4 or sha256(dump[at:at + clen]) != p["code_sha256"]:
                continue
            want = p.get("tables_head_crc", TABLES_HEAD_CRC)
            if heads is None:
                heads = {}
                for i in range(0, len(dump) - 64, 4):
                    heads.setdefault(zlib.crc32(dump[i:i + 64]), []).append(i)
            for t in heads.get(want, []):
                if sha256(dump[t:t + tlen]) == p["tables_sha256"]:
                    return dict(p, kind="progmem", size=PROGMEM_SIZE, code=(PROGMEM_BASE + at, clen, p["code"][2]),
                                tables=(PROGMEM_BASE + t, tlen, p["tables"][2]))
        at = dump.find(sig, at + 1)
    return None


def identify(stock, profiles=None, board=None):
    """The profile a stock file matches (whole-file SHA-256, or a program flash dump by its windows), else None."""
    profiles = PROFILES if profiles is None else profiles
    mine = {h: p for h, p in profiles.items() if board in (None, p["board"])}
    prof = mine.get(sha256(stock))
    if prof is not None and prof.get("kind") != "progmem":
        return prof
    return locate(stock, mine, board)


def parse_slot(slot):
    """The header of a codec slot read back from a radio, checked: magic, version, windows inside the slot and the CRC
    of code, tables and the relocation list. Returns a dict of its fields, else None (an empty or damaged slot, or a
    version 1 slot from before the code moved)."""
    if len(slot) < HEADER_LEN:
        return None
    f = struct.unpack_from("<8I7I4I", slot, 0)
    magic, version, code_off, code_len, run, tab_off, tab_len, tab_ram = f[:8]
    if magic != SLOT_MAGIC or version != SLOT_VERSION:
        return None
    if code_off < HEADER_LEN or code_off + code_len > len(slot) or tab_off + tab_len > len(slot) or not code_len:
        return None
    code, tables = slot[code_off:code_off + code_len], slot[tab_off:tab_off + tab_len]
    crc = zlib.crc32(tables, zlib.crc32(code))
    rel_off, rel_count = f[17], f[18]
    if rel_count > REL_MAX or rel_off % 4 or rel_off + 4 * rel_count > len(slot):
        return None
    rels = list(struct.unpack_from("<%dI" % rel_count, slot, rel_off))
    crc = zlib.crc32(slot[rel_off:rel_off + 4 * rel_count], crc)
    end = max(tab_off + tab_len, rel_off + 4 * rel_count)
    if crc & 0xFFFFFFFF != f[16] or struct.unpack_from("<2I", code, 0) != CODEC_SIG:
        return None
    return {"version": version, "run": run, "tables_ram": tab_ram, "tag": f[15], "crc": f[16], "length": end,
            "relocations": rels, "code_sha256": sha256(code), "tables_sha256": sha256(tables)}


def extract(stock, profiles=None, board=None):
    """Check the stock file and return (profile, code bytes, table bytes)."""
    profiles = PROFILES if profiles is None else profiles
    profiles = {h: p for h, p in profiles.items() if board in (None, p["board"])}
    digest = sha256(stock)
    prof = identify(stock, profiles, board)
    if prof is None:
        raise ExtractError("unsupported stock file (sha256 %s); supported: %s"
                           % (digest, ", ".join("%s (%s...)" % (p["name"], h[:8]) for h, p in profiles.items())))
    magic = prof.get("magic", MAGIC)
    if prof.get("kind") != "progmem" and magic is not None and not stock.startswith(magic):
        raise ExtractError("not a BFUV32-V2 firmware file")
    code, tables = carve(stock, prof)
    if struct.unpack_from("<2I", code, 0) != CODEC_SIG:
        raise ExtractError("codec signature words not found at the code window")
    return prof, code, tables

