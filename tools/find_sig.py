"""
ParkControl Bypass - Pattern Finder
====================================
Run this against a new ParkControl binary to verify existing patterns still
match, or to help locate where to look in IDA when they don't.

Usage:
    python find_patches.py <ParkControl.exe>

Requirements:
    pip install pefile
"""

import sys
import struct
import pefile

# ── Pattern definitions ────────────────────────────────────────────────────────
# Each entry: (name, pattern_bytes, mask_bytes, patch_offsets_description)
# Use None in pattern bytes where mask is 0x00 (wildcard)
PATCHES = [
    {
        "name": "Patch 1 – sub_140004FA0 inner HTTP result check",
        "note": "NOP 'cmp eax,1' at +4, jz->jmp at +7, NOP 'cmp eax,0Dh'+jz at +13",
        "pattern": bytes([
            0x41, 0x8B, 0x45, 0x18,              # mov eax, [r13+18h]
            0x83, 0xF8, 0x01,                    # cmp eax, 1
            0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, # jz success (wildcarded)
            0x83, 0xF8, 0x0D,                    # cmp eax, 0Dh
            0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, # jz success (wildcarded)
        ]),
        "mask": bytes([
            0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ]),
    },
    {
        "name": "Patch 2 – DialogFunc format check gate",
        "note": "NOP 'cmp al,1' + 'jnz failure' at +15 (8 bytes)",
        "pattern": bytes([
            0x48, 0x8B, 0x5C, 0x24, 0x40,        # mov rbx, [rsp+var_C90]
            0x48, 0x8B, 0x4C, 0x24, 0x38,        # mov rcx, [rsp+var_C98]
            0xE8, 0x00, 0x00, 0x00, 0x00,        # call sub_140004380 (wildcarded)
            0x3C, 0x01,                          # cmp al, 1
            0x0F, 0x85, 0x00, 0x00, 0x00, 0x00, # jnz failure (wildcarded)
        ]),
        "mask": bytes([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        ]),
    },
    {
        "name": "Patch 3 – DialogFunc sub_140004590 result gate",
        "note": "NOP 'cmp eax,1' at +15, jz->jmp at +18",
        "pattern": bytes([
            0x4C, 0x8B, 0x44, 0x24, 0x38,  # mov r8, [rsp+var_C98]
            0x48, 0x8B, 0xD3,              # mov rdx, rbx
            0xE8, 0x00, 0x00, 0x00, 0x00, # call sub_140004590 (wildcarded)
            0x8B, 0xF0,                   # mov esi, eax
            0x83, 0xF8, 0x01,             # cmp eax, 1
            0x74, 0x2A,                   # jz success (+0x2A)
        ]),
        "mask": bytes([
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xFF,
            0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ]),
    },
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def find_pattern(data: bytes, pattern: bytes, mask: bytes) -> list[int]:
    """Return all file offsets where pattern matches under mask."""
    results = []
    plen = len(pattern)
    for i in range(len(data) - plen):
        if all((data[i + j] == pattern[j]) or (mask[j] == 0x00)
               for j in range(plen)):
            results.append(i)
    return results


def file_offset_to_rva(pe: pefile.PE, offset: int) -> int | None:
    """Convert a raw file offset to an RVA."""
    for section in pe.sections:
        start = section.PointerToRawData
        end   = start + section.SizeOfRawData
        if start <= offset < end:
            return offset - start + section.VirtualAddress
    return None


def format_bytes(data: bytes, mask: bytes) -> str:
    """Pretty-print bytes, showing ?? for wildcards."""
    return " ".join("??" if mask[i] == 0x00 else f"{data[i]:02X}"
                    for i in range(len(data)))

# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    path = sys.argv[1]
    print(f"Loading: {path}\n")

    pe   = pefile.PE(path)
    data = pe.get_memory_mapped_image()
    base = pe.OPTIONAL_HEADER.ImageBase

    all_ok = True

    for patch in PATCHES:
        print(f"{'─' * 60}")
        print(f"  {patch['name']}")
        print(f"  {patch['note']}")
        print(f"  Pattern: {format_bytes(patch['pattern'], patch['mask'])}")

        matches = find_pattern(data, patch["pattern"], patch["mask"])

        if not matches:
            print("  ✗  NOT FOUND — pattern needs updating")
            all_ok = False
        elif len(matches) > 1:
            print(f"AMBIGUOUS — {len(matches)} matches found (pattern too short):")
            for m in matches:
                rva = file_offset_to_rva(pe, m)
                va  = base + rva if rva is not None else "?"
                print(f"       file+0x{m:X}  RVA=0x{rva:X}  VA=0x{va:X}")
            all_ok = False
        else:
            rva = file_offset_to_rva(pe, matches[0])
            va  = base + rva if rva is not None else "?"
            print(f"  ✓  UNIQUE match at file+0x{matches[0]:X}  RVA=0x{rva:X}  VA=0x{va:X}")

        print()

    print("─" * 60)
    if all_ok:
        print("All patterns matched uniquely. No update needed.")
    else:
        print("One or more patterns need updating.")

    pe.close()


if __name__ == "__main__":
    main()