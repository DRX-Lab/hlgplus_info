import sys
import os
import argparse
from collections import defaultdict

def section(title: str):
    print("│")
    print(f"├─ {title}")

def kv(k: str, v, pad: int = 28, last: bool = False):
    branch = "└" if last else "├"
    print(f"│  {branch}─ {k.ljust(pad)}: {v}")

def error(msg: str, code: int = 1):
    print("│")
    print(f"├─ ✖ {msg}")
    sys.exit(code)

START3 = b"\x00\x00\x01"
START4 = b"\x00\x00\x00\x01"

NAL_AUD = 35
NAL_PREFIX_SEI = 39

SEI_USER_DATA_REGISTERED_ITU_T_T35 = 4

T35_COUNTRY_CODE = 0xB5
T35_PROVIDER_CODE = 0x003C

DEFAULT_PROFILE_LABEL = "A"

def iter_nals(data: bytes):
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

def nal_type(nal: bytes) -> int:
    return (nal[0] >> 1) & 0x3F if nal else -1

def is_vcl(t: int) -> bool:
    return 0 <= t <= 31

def remove_epb(b: bytes) -> bytes:
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

class BitReader:
    __slots__ = ("data", "bitpos")

    def __init__(self, data: bytes):
        self.data = data
        self.bitpos = 0

    def bits_left(self) -> int:
        return len(self.data) * 8 - self.bitpos

    def read_bits(self, n: int) -> int:
        if n <= 0:
            return 0
        if self.bits_left() < n:
            raise ValueError("Not enough bits")
        v = 0
        for _ in range(n):
            byte_i = self.bitpos >> 3
            bit_i = 7 - (self.bitpos & 7)
            v = (v << 1) | ((self.data[byte_i] >> bit_i) & 1)
            self.bitpos += 1
        return v

    def read_bit(self) -> int:
        return self.read_bits(1)

def first_slice_flag_from_vcl(nal: bytes) -> bool:
    if len(nal) < 3:
        return False
    rbsp = remove_epb(nal[2:])
    if not rbsp:
        return False
    try:
        br = BitReader(rbsp)
        return bool(br.read_bit())
    except Exception:
        return False

def parse_sei_messages(rbsp: bytes):
    i = 0
    n = len(rbsp)
    while i < n:
        if i == n - 1 and rbsp[i] == 0x80:
            break

        pt = 0
        while i < n and rbsp[i] == 0xFF:
            pt += 255
            i += 1
        if i >= n:
            break
        pt += rbsp[i]
        i += 1

        sz = 0
        while i < n and rbsp[i] == 0xFF:
            sz += 255
            i += 1
        if i >= n:
            break
        sz += rbsp[i]
        i += 1

        if i + sz > n:
            break

        payload = rbsp[i:i+sz]
        i += sz
        yield pt, payload

def parse_itu_t_t35(payload: bytes):
    if not payload or len(payload) < 1:
        return None

    idx = 0
    cc = payload[idx]
    idx += 1

    if cc == 0xFF:
        if idx >= len(payload):
            return None
        idx += 1

    if idx + 2 > len(payload):
        return None
    pc = int.from_bytes(payload[idx:idx+2], "big")
    idx += 2

    if idx + 2 > len(payload):
        return None
    oc = int.from_bytes(payload[idx:idx+2], "big")
    idx += 2

    if idx + 2 > len(payload):
        return None
    app_id = payload[idx]
    app_ver = payload[idx + 1]
    idx += 2

    return {
        "country_code": cc,
        "provider_code": pc,
        "oriented_code": oc,
        "app_id": app_id,
        "app_ver": app_ver,
        "app_data": payload[idx:],
    }

def is_st2094_app4_signature(t35: dict) -> bool:
    return bool(t35) and t35["country_code"] == T35_COUNTRY_CODE and t35["provider_code"] == T35_PROVIDER_CODE

def parse_app4_window0_stats(app_data: bytes):
    if not app_data:
        return None
    try:
        br = BitReader(app_data)

        num_windows = br.read_bits(2)
        targeted_max_lum = br.read_bits(27)
        peak_flag = br.read_bit()
        if peak_flag:
            return {
                "num_windows": num_windows,
                "targeted_max_lum": targeted_max_lum,
                "note": "actual_peak_luminance_flag=1 (window stats not parsed)",
            }

        m0 = br.read_bits(17)
        m1 = br.read_bits(17)
        m2 = br.read_bits(17)
        avg = br.read_bits(17)

        return {
            "num_windows": num_windows,
            "targeted_max_lum": targeted_max_lum,
            "maxscl": (m0, m1, m2),
            "average_maxrgb": avg,
        }
    except Exception:
        return None

class AuTracker:
    def __init__(self, use_aud: bool):
        self.use_aud = use_aud
        self.au = -1

    def feed(self, nal: bytes):
        t = nal_type(nal)

        if self.use_aud:
            if t == NAL_AUD:
                self.au += 1
                return self.au, True
            return self.au, False

        if is_vcl(t):
            first_slice = first_slice_flag_from_vcl(nal)
            if self.au == -1:
                self.au = 0
                return self.au, True
            if first_slice:
                self.au += 1
                return self.au, True

        return self.au, False

def detect_aud(nals):
    return any(nal_type(n) == NAL_AUD for n in nals)

def safe_div(a, b):
    return (a / b) if b else 0.0

def mode_from_counts(counts: dict, default=None):
    if not counts:
        return default
    return max(counts.items(), key=lambda x: x[1])[0]

def build_hdr_format(profile_label: str, app_ver: int | None):
    short = f"SMPTE ST 2094 App 4, HLG+ Profile {profile_label}"
    full = short if app_ver is None else f"SMPTE ST 2094 App 4, HLG+ Profile {profile_label}, Version {app_ver}"
    return short, full

def cmd_info(args):
    if not os.path.exists(args.input):
        error("Input file not found")

    data = open(args.input, "rb").read()
    nals = list(iter_nals(data))
    if not nals:
        error("No Annex-B NAL units found")

    has_aud = detect_aud(nals)
    tracker = AuTracker(has_aud)

    file_name = os.path.basename(args.input)
    total_aus = 0
    vcl_nals = 0
    sei_prefix_nals = 0

    msgs = 0
    msgs_before_first_vcl = 0
    seen_first_vcl = False
    per_au = defaultdict(int)

    unique_payloads = set()
    last_payload = None
    run_len = 0
    runs = []

    oriented_counts = defaultdict(int)
    app_id_counts = defaultdict(int)
    app_ver_counts = defaultdict(int)

    window0 = None

    current_au = -1

    for nal in nals:
        au, started = tracker.feed(nal)
        if started:
            current_au = au
            total_aus = max(total_aus, current_au + 1)

        t = nal_type(nal)

        if is_vcl(t):
            vcl_nals += 1
            seen_first_vcl = True

        if t == NAL_PREFIX_SEI and len(nal) > 2:
            sei_prefix_nals += 1
            rbsp = remove_epb(nal[2:])

            for pt, payload in parse_sei_messages(rbsp):
                if pt != SEI_USER_DATA_REGISTERED_ITU_T_T35:
                    continue

                t35 = parse_itu_t_t35(payload)
                if not t35:
                    continue

                oriented_counts[t35["oriented_code"]] += 1
                app_id_counts[t35["app_id"]] += 1
                app_ver_counts[t35["app_ver"]] += 1

                if not is_st2094_app4_signature(t35):
                    continue

                msgs += 1
                per_au[current_au] += 1

                if not seen_first_vcl:
                    msgs_before_first_vcl += 1

                unique_payloads.add(payload)

                if payload == last_payload:
                    run_len += 1
                else:
                    if run_len > 0:
                        runs.append(run_len)
                    last_payload = payload
                    run_len = 1

                if window0 is None:
                    parsed = parse_app4_window0_stats(t35.get("app_data", b""))
                    if parsed and ("maxscl" in parsed or "note" in parsed):
                        window0 = parsed

    if run_len > 0:
        runs.append(run_len)

    aus_with_meta = sum(1 for _, c in per_au.items() if c > 0)
    coverage = safe_div(aus_with_meta, total_aus) if total_aus else 0.0

    counts = list(per_au.values()) if per_au else []
    min_per = min(counts) if counts else 0
    max_per = max(counts) if counts else 0
    avg_per = safe_div(sum(counts), len(counts)) if counts else 0.0

    if msgs > 0 and len(unique_payloads) == 1:
        meta_type = "Static"
    elif len(unique_payloads) > 1:
        meta_type = "Dynamic"
    else:
        meta_type = "Unknown"
    longest_run = max(runs) if runs else 0

    oriented_mode = mode_from_counts(oriented_counts)
    app_id_mode = mode_from_counts(app_id_counts)
    app_ver_mode = mode_from_counts(app_ver_counts)

    hdr_short = hdr_full = None
    if msgs > 0 and app_id_mode == 4:
        hdr_short, hdr_full = build_hdr_format(args.profile, app_ver_mode)
    elif msgs > 0:
        hdr_short, hdr_full = build_hdr_format(args.profile, None)

    section("HLG+ / SMPTE ST 2094 App 4 Bitstream Report")
    kv("File", file_name)
    kv("Frames (AUs)", total_aus)
    kv("Metadata Messages", msgs)
    kv("Coverage", f"{aus_with_meta}/{total_aus} ({coverage*100:.0f}%)", last=True)

    section("HDR Format")
    if hdr_short:
        kv("Format", hdr_short)
        kv("Version", app_ver_mode if app_id_mode == 4 else "Unknown", last=True)
    else:
        kv("Format", "Unknown (no ST 2094 App 4 detected)", last=True)

    section("Window(0) Sample")
    if window0 and "maxscl" in window0:
        m0, m1, m2 = window0["maxscl"]
        avgm = window0["average_maxrgb"]
        kv("MaxSCL [R,G,B]", f"{m0}, {m1}, {m2}")
        kv("MaxSCL (nits)", f"{m0/10:.1f}, {m1/10:.1f}, {m2/10:.1f}")
        kv("Average MaxRGB", f"{avgm}")
        kv("Average MaxRGB (nits)", f"{avgm/10:.1f}", last=True)
    elif window0 and "note" in window0:
        kv("Note", window0["note"], last=True)
    else:
        kv("Window stats", "Not parsed", last=True)

    section("Stream Structure")
    kv("VCL NAL Units", vcl_nals)
    kv("Prefix SEI NAL Units", sei_prefix_nals)
    kv("AUD Present", "Yes" if has_aud else "No", last=True)

    section("Metadata Details")
    kv("Messages Before First Frame", msgs_before_first_vcl)
    kv("Per-Frame Density", f"min={min_per}, max={max_per}, avg={avg_per:.2f}")
    kv("Type", meta_type)
    kv("Unique Payloads", len(unique_payloads))
    kv("Longest Identical Run", f"{longest_run} frames", last=True)

    section("T.35 Header Summary")
    kv("Country Code", f"0x{T35_COUNTRY_CODE:02X}")
    kv("Provider Code", f"0x{T35_PROVIDER_CODE:04X}")
    kv("Oriented Code", f"0x{oriented_mode:04X}" if oriented_mode is not None else "Unknown")
    kv("Application ID", app_id_mode if app_id_mode is not None else "Unknown")
    kv("Application Version", app_ver_mode if app_ver_mode is not None else "Unknown", last=True)

    print("│")
    print("└─ Result")
    if total_aus > 0 and aus_with_meta == total_aus and msgs > 0 and app_id_mode == 4:
        print(f"   └─ PASS — ST 2094 App 4 metadata present on every frame (HLG+ Profile {args.profile} compliant)")
    elif msgs > 0:
        print("   └─ PARTIAL — ST 2094 metadata detected but coverage is incomplete")
    else:
        print("   └─ FAIL — No ST 2094 App 4 metadata detected")

def main():
    p = argparse.ArgumentParser(prog="hlgplus_info", description="HLG+ / SMPTE ST 2094 App 4 HEVC bitstream info tool (Annex-B)")
    subs = p.add_subparsers(dest="cmd", required=True)
    sp = subs.add_parser("info", help="Bitstream readiness report")
    sp.add_argument("-i", "--input", required=True, help="Input .hevc/.h265 (Annex-B)")
    sp.add_argument("--profile", default=DEFAULT_PROFILE_LABEL, help="HLG+ Profile label to print (default: A)")
    sp.set_defaults(func=cmd_info)
    args = p.parse_args()
    args.func(args)
if __name__ == "__main__":
    main()
