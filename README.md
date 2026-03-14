# ParkControl License Bypass

A DLL that patches ParkControl's license validation at runtime using byte pattern matching.

## How It Works

Three byte patches are applied at startup via `DllMain`:

**Patch 1 - Inner HTTP result check** (`sub_140004FA0`)  
Forces the HTTP license response check to always report success by converting the conditional `jz success` into an unconditional jump and NOPing the fallback check.

    mov  eax, [r13+18h]   ; result code from HTTP response
    cmp  eax, 1           ; <- NOPed
    jz   success          ; <- converted to unconditional jmp
    cmp  eax, 0Dh         ; <- NOPed
    jz   success          ; <- NOPed

**Patch 2 - Activation code format gate** (`DialogFunc`)  
Bypasses the format validator (`sub_140004380`) so any string entered in the activation dialog is accepted.

    call sub_140004380    ; format validator
    cmp  al, 1            ; <- NOPed
    jnz  failure          ; <- NOPed

**Patch 3 - Activation handler return value gate** (`DialogFunc`)  
Forces the outer activation handler (`sub_140004590`) return value check to always take the success branch.

    call sub_140004590    ; outer activation handler
    mov  esi, eax
    cmp  eax, 1           ; <- NOPed
    jz   success          ; <- opcode changed to unconditional jmp

All patches are located at runtime via masked byte pattern search, so they survive address space layout randomization and work across multiple binary versions without recompilation.

---

## Usage

1. Place `version.dll` in the same directory as `ParkControl.exe` it proxies the real `version.dll` automatically
2. Launch `ParkControl.exe`
3. Open the activation dialog and enter any text for the name and activation code
4. Click Activate now
5. You should see a successful activation window returned.
6. You can remove the DLL after activation or leave it in the Park Control root directory.

---

## Updating for a New Version

Run the pattern checker first if all three show OK no changes are needed:

    .\tools\find_patches.ps1 "C:\Program Files\Bitsum\ParkControl\ParkControl.exe"

If any pattern shows FAIL, follow [IDA Signature Update Guide](tools/IDA_SIG_UPDATE_GUIDE.md) to regenerate it.
