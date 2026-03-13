#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include "MinHook/MinHook.h"
#include "version_proxy.h"

#pragma comment(lib, "Psapi.lib")

namespace {
    // Signature for sub_140004FA0 (main function)
    const uint8_t k_process_license_pattern[] = { 0x48, 0x8B, 0xC4, 0x4C, 0x89, 0x48, 0x20, 0x44 };
    const uint8_t k_process_license_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const size_t k_process_license_pattern_size = sizeof(k_process_license_pattern);

    // Signature for sub_140002E50
    const uint8_t k_sub_140002E90_pattern[] = { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x65 };
    const uint8_t k_sub_140002E90_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const size_t k_sub_140002E90_pattern_size = sizeof(k_sub_140002E90_pattern);

    // Signature for sub_140003440
    const uint8_t k_sub_140003470_pattern[] = { 0x48, 0x83, 0xEC, 0x28, 0x8B, 0xD1 };
    const uint8_t k_sub_140003470_mask[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    const size_t k_sub_140003470_pattern_size = sizeof(k_sub_140003470_pattern);

    // Function pointer types
    using process_license_t = uint8_t(__fastcall*)(int64_t request_context, int64_t license_key, char is_activation, int64_t* output_license);
    using sub_140002E90_t = int64_t(__fastcall*)();
    using sub_140003470_t = void(__fastcall*)(int64_t errorCode);

    // Original function pointers
    process_license_t original_process_license = nullptr;
    sub_140002E90_t sub_140002E90 = nullptr;
    sub_140003470_t sub_140003470 = nullptr;

    // Global variables for thread management
    HANDLE g_main_thread = nullptr;
    HMODULE g_hmodule = nullptr;
    volatile bool g_running = true;
}

// Debug logging function
void debug_log(const std::string& message) {
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

// Debug log with hex formatting
void debug_log_hex(const std::string& prefix, const void* ptr) {
    std::ostringstream oss;
    oss << prefix << "0x" << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(ptr);
    debug_log(oss.str());
}

// Stub implementations for subfunctions (used if signature scanning fails)
int64_t __fastcall stub_sub_140002E90() {
    debug_log("stub_sub_140002E90: Using stub implementation");
    static int64_t dummy_object = 0x1000;
    return dummy_object;
}

void __fastcall stub_sub_140003470(int64_t errorCode) {
    std::ostringstream oss;
    oss << "stub_sub_140003470: Called with errorCode=0x" << std::hex << errorCode;
    debug_log(oss.str());
}

// Function to search for a byte pattern with a mask
void* find_pattern(HMODULE module, const uint8_t* pattern, const uint8_t* mask, size_t pattern_size) {
    MODULEINFO module_info;
    if (!GetModuleInformation(GetCurrentProcess(), module, &module_info, sizeof(module_info))) {
        debug_log("find_pattern: ERROR - GetModuleInformation failed");
        return nullptr;
    }

    uint8_t* start_address = static_cast<uint8_t*>(module_info.lpBaseOfDll);
    size_t size = module_info.SizeOfImage;

    for (size_t i = 0; i < size - pattern_size; ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern_size; ++j) {
            if (mask[j] == 0xFF && pattern[j] != start_address[i + j]) {
                found = false;
                break;
            }
        }
        if (found) {
            debug_log_hex("find_pattern: Pattern found at ", start_address + i);
            return start_address + i;
        }
    }

    debug_log("find_pattern: ERROR - Pattern not found");
    return nullptr;
}

// Hooked version of process_license
static uint8_t __fastcall hooked_process_license(int64_t request_context, int64_t license_key, char is_activation, int64_t* output_license) {
    debug_log("hooked_process_license: ENTER - hook fired");

    std::ostringstream oss;
    oss << "hooked_process_license: request_context=0x" << std::hex << request_context
        << " license_key=0x" << license_key
        << " is_activation=" << static_cast<int>(is_activation);
    debug_log(oss.str());

    uint8_t v5 = 1; // Force success return value

    int64_t v18 = sub_140002E90();
    if (!v18) {
        debug_log("hooked_process_license: sub_140002E90 returned null, calling sub_140003470");
        sub_140003470(2147500037i64);
        return 0;
    }

    debug_log("hooked_process_license: sub_140002E90 succeeded, patching output");

    if (output_license) {
        try {
            int64_t* v33 = (int64_t*)((*(int64_t(__fastcall**)(int64_t))(*(uint64_t*)v18 + 24i64))(v18) + 24);
            *output_license = (int64_t)(v33 + 6);
            debug_log("hooked_process_license: output_license patched successfully");
        }
        catch (...) {
            debug_log("hooked_process_license: EXCEPTION patching output_license");
            return 0;
        }
    }

    if (request_context) {
        try {
            *(DWORD*)(request_context + 24) = 1;
            *(BYTE*)(request_context + 48) = 0;
            debug_log("hooked_process_license: request_context patched successfully");
        }
        catch (...) {
            debug_log("hooked_process_license: EXCEPTION patching request_context");
            return 0;
        }
    }

    debug_log("hooked_process_license: returning success");
    return v5;
}

bool initialize_hook() {
    MH_STATUS mh_status = MH_Initialize();
    if (mh_status != MH_OK) {
        debug_log("initialize_hook: ERROR - MH_Initialize failed");
        return false;
    }

    HMODULE module = GetModuleHandle(nullptr);
    if (!module) {
        debug_log("initialize_hook: ERROR - GetModuleHandle failed");
        return false;
    }

    sub_140002E90 = reinterpret_cast<sub_140002E90_t>(find_pattern(module, k_sub_140002E90_pattern, k_sub_140002E90_mask, k_sub_140002E90_pattern_size));
    if (!sub_140002E90) {
        sub_140002E90 = stub_sub_140002E90;
    }

    sub_140003470 = reinterpret_cast<sub_140003470_t>(find_pattern(module, k_sub_140003470_pattern, k_sub_140003470_mask, k_sub_140003470_pattern_size));
    if (!sub_140003470) {
        sub_140003470 = stub_sub_140003470;
    }

    void* target_function = find_pattern(module, k_process_license_pattern, k_process_license_mask, k_process_license_pattern_size);
    if (!target_function) {
        debug_log("initialize_hook: ERROR - process_license function not found");
        return false;
    }

    mh_status = MH_CreateHook(target_function, &hooked_process_license, reinterpret_cast<LPVOID*>(&original_process_license));
    if (mh_status != MH_OK) {
        debug_log("initialize_hook: ERROR - MH_CreateHook failed");
        return false;
    }

    mh_status = MH_EnableHook(target_function);
    if (mh_status != MH_OK) {
        debug_log("initialize_hook: ERROR - MH_EnableHook failed");
        return false;
    }

    return true;
}

void cleanup_hook() {
    HMODULE module = GetModuleHandle(nullptr);
    if (module) {
        void* target_function = find_pattern(module, k_process_license_pattern, k_process_license_mask, k_process_license_pattern_size);
        if (target_function) {
            MH_DisableHook(target_function);
        }
    }
    MH_Uninitialize();
}

DWORD WINAPI main_thread(LPVOID) {
    if (!initialize_hook()) {
        FreeLibraryAndExitThread(g_hmodule, 1);
        return 1;
    }

    while (g_running) {
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            g_running = false;
        }
        Sleep(75);
    }

    cleanup_hook();
    FreeLibraryAndExitThread(g_hmodule, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason_for_call, LPVOID reserved) {
    switch (reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hmodule = module;
        version_proxy::load();
        DisableThreadLibraryCalls(module);
        g_main_thread = CreateThread(nullptr, 0, main_thread, nullptr, 0, nullptr);
        if (!g_main_thread) {
            return FALSE;
        }
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