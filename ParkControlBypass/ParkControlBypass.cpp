#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include "version_proxy.h"

#pragma comment(lib, "Psapi.lib")

// ============================================================
//  HOW TO UPDATE FOR A NEW VERSION OF PARKCONTROL
//
//  1. Open the new binary in IDA Pro
//  2. Run SigMakerEx on each function listed below
//  3. Find the siglet offsets noted in each patch entry
//  4. Update the pattern/mask bytes accordingly
//
//  Functions of interest:
//    - sub_140004FA0  (inner HTTP result check)
//    - DialogFunc     (activation dialog, ~0x1400151B0)
//    - sub_140004380  (activation code format validator)
//    - sub_140004590  (outer activation handler)
//    - sub_140005B20  (HTTP executor, writes [rcx+18h])
// ============================================================

namespace {
    // ----------------------------------------------------------
    // Patch 1: sub_140004FA0 - inner HTTP result check
    //
    // IDA location : sub_140004FA0
    // Relevant siglets:
    //   mov  eax, [r13+18h]    <- result code written by sub_140005B20
    //   cmp  eax, 1
    //   jz   success           <- we convert this to unconditional jmp
    //   cmp  eax, 0Dh
    //   jz   success           <- we NOP this
    //
    // Strategy: NOP "cmp eax,1", convert first jz->jmp, NOP second cmp+jz
    // ----------------------------------------------------------
    const uint8_t k_inner_pattern[] = {
        0x41, 0x8B, 0x45, 0x18,              // mov eax, [r13+18h]
        0x83, 0xF8, 0x01,                    // cmp eax, 1
        0x0F, 0x84, 0x00, 0x00, 0x00, 0x00, // jz success (rel32 wildcarded)
        0x83, 0xF8, 0x0D,                    // cmp eax, 0Dh
        0x0F, 0x84, 0x00, 0x00, 0x00, 0x00  // jz success (rel32 wildcarded)
    };
    const uint8_t k_inner_mask[] = {
        0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    };

    // ----------------------------------------------------------
    // Patch 2: DialogFunc - activation code format gate
    //
    // IDA location : DialogFunc, siglets [0140-0144]
    //   mov  rbx, [rsp+var_C90]  <- anchor
    //   mov  rcx, [rsp+var_C98]  <- anchor
    //   call sub_140004380       <- format validator (wildcarded)
    //   cmp  al, 1               <- patch target (+15)
    //   jnz  loc_14001592D       <- patch target (+17), rel32 wildcarded
    //
    // Strategy: NOP "cmp al,1" + "jnz failure" (8 bytes at +15)
    // ----------------------------------------------------------
    const uint8_t k_format_pattern[] = {
        0x48, 0x8B, 0x5C, 0x24, 0x40,        // mov rbx, [rsp+var_C90]
        0x48, 0x8B, 0x4C, 0x24, 0x38,        // mov rcx, [rsp+var_C98]
        0xE8, 0x00, 0x00, 0x00, 0x00,        // call sub_140004380
        0x3C, 0x01,                          // cmp al, 1
        0x0F, 0x85, 0x00, 0x00, 0x00, 0x00  // jnz failure
    };
    const uint8_t k_format_mask[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00
    };

    // ----------------------------------------------------------
    // Patch 3: DialogFunc - sub_140004590 return value gate
    //
    // IDA location : DialogFunc, siglets [0184-0189]
    //   mov  r8,  [rsp+var_C98]  <- anchor
    //   mov  rdx, rbx            <- anchor
    //   call sub_140004590       <- outer activation handler (wildcarded)
    //   mov  esi, eax            <- save return value
    //   cmp  eax, 1              <- patch target (+15)
    //   jz   success             <- patch target (+18), rel8=0x2A
    //
    // Strategy: NOP "cmp eax,1", change "jz" -> "jmp" (same rel8)
    // ----------------------------------------------------------
    const uint8_t k_dialog_result_pattern[] = {
        0x4C, 0x8B, 0x44, 0x24, 0x38,  // mov r8, [rsp+var_C98]
        0x48, 0x8B, 0xD3,              // mov rdx, rbx
        0xE8, 0x00, 0x00, 0x00, 0x00, // call sub_140004590
        0x8B, 0xF0,                   // mov esi, eax
        0x83, 0xF8, 0x01,             // cmp eax, 1
        0x74, 0x2A                    // jz  success (+0x2A)
    };
    const uint8_t k_dialog_result_mask[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF,
        0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF,
        0xFF, 0xFF, 0xFF,
        0xFF, 0xFF
    };

    HANDLE        g_main_thread = nullptr;
    HMODULE       g_hmodule = nullptr;
    volatile bool g_running = true;
}

static void debug_log(const std::string& message) {
    std::ofstream log_file("debug.log", std::ios::app);
    if (log_file.is_open()) {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

        struct tm tm_info;
        localtime_s(&tm_info, &time_t);

        log_file << "[" << std::put_time(&tm_info, "%Y-%m-%d %H:%M:%S")
            << "." << std::setfill('0') << std::setw(3) << ms.count()
            << "] " << message << std::endl;
        log_file.close();
    }
}

static void debug_log_hex(const std::string& prefix, const void* ptr) {
    std::ostringstream oss;
    oss << prefix << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(ptr);
    debug_log(oss.str());
}

static void* find_pattern(HMODULE module, const uint8_t* pattern, const uint8_t* mask, size_t size) {
    MODULEINFO mi = {};
    if (!GetModuleInformation(GetCurrentProcess(), module, &mi, sizeof(mi))) {
        debug_log("find_pattern: ERROR - GetModuleInformation failed");
        return nullptr;
    }

    auto* base = static_cast<uint8_t*>(mi.lpBaseOfDll);

    for (size_t i = 0; i < mi.SizeOfImage - size; ++i) {
        bool found = true;
        for (size_t j = 0; j < size; ++j) {
            if (mask[j] == 0xFF && pattern[j] != base[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            debug_log_hex("find_pattern: found at ", base + i);
            return base + i;
        }
    }

    debug_log("find_pattern: ERROR - not found");
    return nullptr;
}

static bool patch_bytes(void* address, const uint8_t* bytes, size_t count) {
    DWORD old_protect;
    if (!VirtualProtect(address, count, PAGE_EXECUTE_READWRITE, &old_protect)) {
        debug_log("patch_bytes: ERROR - VirtualProtect failed");
        return false;
    }
    memcpy(address, bytes, count);
    FlushInstructionCache(GetCurrentProcess(), address, count);
    VirtualProtect(address, count, old_protect, &old_protect);
    return true;
}

// Patch 1: sub_140004FA0 - always take the success branch after HTTP call
static bool apply_inner_patch(HMODULE module) {
    void* match = find_pattern(module, k_inner_pattern, k_inner_mask, sizeof(k_inner_pattern));
    if (!match) { debug_log("apply_inner_patch: ERROR - pattern not found"); return false; }

    auto* base = static_cast<uint8_t*>(match);

    // NOP "cmp eax, 1" at +4
    const uint8_t nop3[] = { 0x90, 0x90, 0x90 };
    if (!patch_bytes(base + 4, nop3, sizeof(nop3))) return false;

    // jz -> jmp at +7: rel32 grows by 1 due to opcode size change (0F 84 -> E9)
    int32_t rel32 = *reinterpret_cast<int32_t*>(base + 9) + 1;
    uint8_t jmp[6] = { 0xE9, 0x00, 0x00, 0x00, 0x00, 0x90 };
    memcpy(&jmp[1], &rel32, sizeof(rel32));
    if (!patch_bytes(base + 7, jmp, sizeof(jmp))) return false;

    // NOP "cmp eax, 0Dh" + second jz at +13 (9 bytes)
    const uint8_t nop9[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    if (!patch_bytes(base + 13, nop9, sizeof(nop9))) return false;

    debug_log_hex("apply_inner_patch: OK at ", match);
    return true;
}

// Patch 2: DialogFunc - bypass activation code format validation
static bool apply_format_check_patch(HMODULE module) {
    void* match = find_pattern(module, k_format_pattern, k_format_mask, sizeof(k_format_pattern));
    if (!match) { debug_log("apply_format_check_patch: ERROR - pattern not found"); return false; }

    // NOP "cmp al, 1" (2 bytes at +15) + "jnz failure" (6 bytes at +17) = 8 bytes
    const uint8_t nop8[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    if (!patch_bytes(static_cast<uint8_t*>(match) + 15, nop8, sizeof(nop8))) return false;

    debug_log_hex("apply_format_check_patch: OK at ", match);
    return true;
}

// Patch 3: DialogFunc - force sub_140004590 result check to always succeed
static bool apply_dialog_result_patch(HMODULE module) {
    void* match = find_pattern(module, k_dialog_result_pattern, k_dialog_result_mask, sizeof(k_dialog_result_pattern));
    if (!match) { debug_log("apply_dialog_result_patch: ERROR - pattern not found"); return false; }

    auto* base = static_cast<uint8_t*>(match);

    // NOP "cmp eax, 1" at +15 (3 bytes)
    const uint8_t nop3[] = { 0x90, 0x90, 0x90 };
    if (!patch_bytes(base + 15, nop3, sizeof(nop3))) return false;

    // "jz +2A" -> "jmp +2A" at +18 (change opcode 0x74 -> 0xEB, rel8 unchanged)
    const uint8_t jmp[] = { 0xEB };
    if (!patch_bytes(base + 18, jmp, sizeof(jmp))) return false;

    debug_log_hex("apply_dialog_result_patch: OK at ", match);
    return true;
}

static bool initialize_patch() {
    HMODULE module = GetModuleHandle(nullptr);
    if (!module) { debug_log("initialize_patch: ERROR - GetModuleHandle failed"); return false; }

    if (!apply_inner_patch(module))         return false;
    if (!apply_format_check_patch(module))  return false;
    if (!apply_dialog_result_patch(module)) return false;

    debug_log("initialize_patch: all patches applied successfully");
    return true;
}

static DWORD WINAPI main_thread(LPVOID) {
    while (g_running) {
        if (GetAsyncKeyState(VK_END) & 0x8000)
            g_running = false;
        Sleep(75);
    }
    FreeLibraryAndExitThread(g_hmodule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason_for_call, LPVOID reserved) {
    switch (reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hmodule = module;
        version_proxy::load();
        DisableThreadLibraryCalls(module);

        if (!initialize_patch())
            return FALSE;

        g_main_thread = CreateThread(nullptr, 0, main_thread, nullptr, 0, nullptr);
        if (!g_main_thread)
            return FALSE;
        break;

    case DLL_PROCESS_DETACH:
        g_running = false;
        if (g_main_thread) {
            WaitForSingleObject(g_main_thread, 1000);
            CloseHandle(g_main_thread);
        }
        version_proxy::unload();
        break;
    }
    return TRUE;
}