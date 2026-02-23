#!/usr/bin/env python3
# hlgplus_info.py
#
# HLG+ / HDR10+ HEVC Annex-B bitstream INFO tool

import sys
import os
import argparse
from collections import defaultdict 

def section(title):
    print("│")
    print(f"├─ {title}")

def kv(k, v, pad=34):
    print(f"│  ├─ {k.ljust(pad)}: {v}")

def kv_end(k, v, pad=34):
    print(f"│  └─ {k.ljust(pad)}: {v}")

def sub(title):
    print(f"│  ├─ {title}")

def item(msg):
    print(f"│  │  └─ {msg}")

def error(msg, code=1):
    print("│")
    print(f"├─ ✖ {msg}")
    sys.exit(code) 

START3 = b"\x00\x00\x01"
START4 = b"\x00\x00\x00\x01"

# HDR10+ (SMPTE ST 2094-40)
HDR10P_CC = 0xB5
HDR10P_PC = 0x003C 

def iter_nals(data):
    i = 0
    n = len(data)
    while i < n - 4:
        if data[i:i+4] == START4:
            sc = 4
        elif data[i:i+3] == START3:
            sc = 3
        else:
            i += 1
            continue
        j = i + sc
        k = j
        while k < n - 4 and data[k:k+3] not in (START3, START4):
            k += 1
        yield data[j:k]
        i = k

def nal_type(nal):
    return (nal[0] >> 1) & 0x3F if nal else -1

def is_vcl(t):
    return 0 <= t <= 31 

def remove_epb(b):
    out = bytearray()
    zeros = 0
    for x in b:
        if zeros == 2 and x == 3:
            zeros = 0
            continue
        out.append(x)
        zeros = zeros + 1 if x == 0 else 0
        if zeros > 2:
            zeros = 2
    return bytes(out)

def parse_sei(rbsp):
    i = 0
    n = len(rbsp)
    while i < n:
        if i == n - 1 and rbsp[i] == 0x80:
            break

        pt = 0
        while rbsp[i] == 0xFF:
            pt += 255
            i += 1
        pt += rbsp[i]; i += 1

        sz = 0
        while rbsp[i] == 0xFF:
            sz += 255
            i += 1
        sz += rbsp[i]; i += 1

        payload = rbsp[i:i+sz]
        i += sz
        yield pt, payload

def is_hdr10plus(payload):
    return (
        payload and
        len(payload) >= 3 and
        payload[0] == HDR10P_CC and
        int.from_bytes(payload[1:3], "big") == HDR10P_PC
    ) 

class AuTracker:
    def __init__(self, use_aud):
        self.use_aud = use_aud
        self.au = -1
        self.saw_vcl = False

    def feed(self, nal):
        t = nal_type(nal)

        if self.use_aud:
            if t == 35:
                self.au += 1
                return self.au, True
            return self.au, False

        if is_vcl(t):
            self.saw_vcl = True
            first_slice = len(nal) >= 3 and bool(nal[2] & 0x80)
            if self.au == -1:
                self.au = 0
                return self.au, True
            if first_slice:
                self.au += 1
                return self.au, True

        return self.au, False

def detect_aud(nals):
    return any(nal_type(n) == 35 for n in nals) 

def cmd_info(args):
    if not os.path.exists(args.input):
        error("Input file not found")

    data = open(args.input, "rb").read()
    nals = list(iter_nals(data))
    if not nals:
        error("No Annex-B NAL units found")

    has_aud = detect_aud(nals)
    tracker = AuTracker(has_aud)

    total_vcl = total_sei = 0
    hdr10p_msgs = 0
    hdr10p_before_first_vcl = 0

    current_au = -1
    seen_first_vcl = False

    per_au = defaultdict(int)
    unique_payloads = set()
    payload_runs = []
    last_payload = None
    run_len = 0

    for nal in nals:
        au, started = tracker.feed(nal)
        if started:
            current_au = au

        t = nal_type(nal)

        if is_vcl(t):
            total_vcl += 1
            seen_first_vcl = True

        if t == 39 and len(nal) > 2:
            total_sei += 1
            rbsp = remove_epb(nal[2:])
            for pt, payload in parse_sei(rbsp):
                if pt == 4 and is_hdr10plus(payload):
                    hdr10p_msgs += 1
                    per_au[current_au] += 1
                    unique_payloads.add(payload)

                    if not seen_first_vcl:
                        hdr10p_before_first_vcl += 1

                    if payload == last_payload:
                        run_len += 1
                    else:
                        if run_len > 0:
                            payload_runs.append(run_len)
                        last_payload = payload
                        run_len = 1

    if run_len > 0:
        payload_runs.append(run_len)

    longest_static_run = max(payload_runs) if payload_runs else 0 

    section("HLG+ / HDR10+ BITSTREAM INFO")
    kv("File", os.path.basename(args.input))
    kv("Total NAL units", len(nals))
    kv("VCL NAL units", total_vcl)
    kv("SEI prefix NALs", total_sei)
    kv("HDR10+ messages", hdr10p_msgs)
    kv_end("AUD present", has_aud)

    section("HDR10+ Analysis (Test Item #2)")

    sub("Availability")
    item(f"HDR10+ before first VCL: {hdr10p_before_first_vcl}")
    item(f"Frame-level availability: {hdr10p_msgs >= total_vcl}")

    sub("Per-AU density")
    if per_au:
        counts = list(per_au.values())
        item(f"Min per AU: {min(counts)}")
        item(f"Max per AU: {max(counts)}")
        item(f"Avg per AU: {sum(counts)/len(counts):.2f}")
    else:
        item("No AU mapping available")

    sub("Metadata classification (important)")
    if len(unique_payloads) == 1:
        item("Metadata type: Static (expected for Test Item #2)")
    elif len(unique_payloads) > 1:
        item("Metadata type: Dynamic (suitable for Test Item #3)")
    else:
        item("Metadata type: Unknown")

    item(f"Unique HDR10+ payloads: {len(unique_payloads)}")
    item(f"Longest static run: {longest_static_run} frames")

    section("Result")
    if hdr10p_msgs >= total_vcl and total_vcl > 0:
        kv_end(
            "Status",
            "PASS — HDR10+ metadata usable for HLG+ (USB Test Item #2 ready)"
        )
    elif hdr10p_msgs > 0:
        kv_end(
            "Status",
            "PARTIAL — HDR10+ present but incomplete"
        )
    else:
        kv_end(
            "Status",
            "FAIL — No HDR10+ metadata detected"
        ) 

def main():
    p = argparse.ArgumentParser(
        prog="hlgplus_info",
        description="HLG+ / HDR10+ HEVC bitstream info tool"
    )

    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("info", help="HLG+ bitstream readiness report")
    sp.add_argument(
        "-i", "--input",
        required=True,
        help="Input .hevc/.h265 (Annex-B)"
    )
    sp.set_defaults(func=cmd_info)

    args = p.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()