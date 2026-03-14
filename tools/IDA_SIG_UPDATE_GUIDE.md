# IDA Update Guide

Run `find_sig.ps1` or `find_sig.py` against the new binary first:

    .\tools\find_sig.ps1 "C:\Program Files\Bitsum\ParkControl\ParkControl.exe"
    py find_sig.py "C:\Program Files\Bitsum\ParkControl\ParkControl.exe"

If all three show `[OK]` you are done. If any show `[FAIL]` follow the steps below for that patch only.

---

## One-time setup

1. Launch **IDA Pro 64-bit**
2. Load `ParkControl.exe` and wait for analysis to finish
3. Make sure the **SigMakerEx** plugin is installed

---

## Patch 1 — Inner HTTP result check

1. Press `Alt+T` and search for: `%s%s&item_id=%d&license=%s`
2. You land directly in the target function
3. Scroll until you see these two blocks:

        mov  eax, [r13+18h]
        cmp  eax, 1
        jz   loc_somewhere (generally a string of numbers)

        cmp  eax, 0Dh
        jz   loc_somewhere

4. Select the first block from `mov eax, [r13+18h]` to `jz   loc_somewhere`
5. Go to **Edit > Plugins > SigMakerEx**, select **From address range**
6. Click **Continue** and copy the output we'll need this for later
7. Next select the second block from `cmp  eax, 0Dh` to `jz   loc_somewhere`
8. Go to **Edit > Plugins > SigMakerEx**, select **From address range**
9. Click **Continue** and copy the output
10. Add the two signatures together so you have a single string, then
    **convert the IDA hex string to `0x`‑prefixed hexadecimal bytes
    (C-style byte array format)**.

Example:

IDA output:

    41 8B 45 18 83 F8 01 0F 84 5B 01 00 00 83 F8 0D 0F 84 E8 00 00 00

Converted for C++:

``` cpp
0x41, 0x8B, 0x45, 0x18, 0x83, 0xF8, 0x01, 0x0F, 0x84, 0x5B, 0x01, 0x00, 0x00,
0x83, 0xF8, 0x0D, 0x0F, 0x84, 0xE8, 0x00, 0x00, 0x00
```
11. Replace the byte pattern in `k_inner_pattern` with the complete converted string. 

---

## Patch 2 — Format check gate

1. Press `Alt+T` and search for: `purchase-his`
2. You land in `DialogFunc`
3. Scroll up near the top until you see these two blocks:

        mov  rbx, [rsp+something] (The something part will vary, for me it was: [rsp+0CD0h+var_C90])
        mov  rcx, [rsp+something]

        call sub_XXXXXXXX
        cmp  al, 1
        jnz  loc_somewhere

4. Click the `mov rbx` line
5. Select the first block from `mov  rbx, [rsp+something]` to `mov  rcx, [rsp+something]`
6. Go to **Edit > Plugins > SigMakerEx**, select **From address range**
7. Click **Continue** and copy the output we'll need this for later
8. Next select the second block from `call sub_XXXXXXXX` to `jnz  loc_somewhere`
9. Go to **Edit > Plugins > SigMakerEx**, select **From address range**
10. Click **Continue** and copy the output
11. Add the two signatures together so you have a single string, then
    **convert the IDA hex string to `0x`‑prefixed hexadecimal bytes
    (C-style byte array format)**.
12. Replace the byte pattern in `k_format_pattern[]` with the complete converted string. 

---

## Patch 3 — Result gate

1. Either scroll down from the Patch 2 block OR Press `Alt+T` and search for: `purchase-his`
2. If searching for `purchase-his` you'll land in `DialogFunc` again scroll up otherwise, scroll down from the Patch 2 block
3. Scroll passed the Patch 2 block until you see this block:

        mov  r8,  [rsp+something]
        mov  rdx, rbx
        call sub_XXXXXXXX
        mov  esi, eax
        cmp  eax, 1
        jz   short loc_somewhere

4. Select the entire block from `mov  r8,  [rsp+something]` to `jz   short loc_somewhere`
5. Go to **Edit > Plugins > SigMakerEx**, select **From address range**
6. Click **Continue** and copy the output we'll need this for later
7. Convert the IDA hex string to `0x`‑prefixed hexadecimal bytes (C-style byte array format).
8. Replace the byte pattern in `k_dialog_result_pattern[]` with the complete converted string. 

---

## Applying the new signatures

For each pattern you updated:

1. Paste the new hex bytes into the `k_*_pattern[]` array in `ParkControlBypass.cpp`
2. In the matching `k_*_mask[]` array set `0x00` for every `??` and `0xFF` for everything else
3. You can now build the DLL with the updated signatures
4. It's recommended to also update the signatures in `find_sig.ps1` and `find_sig.py` so they continue to work. After updating, you can verify that all three patch signatures show [OK] in future ParkControl binaries.