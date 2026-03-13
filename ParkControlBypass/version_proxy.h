#pragma once
#include <windows.h>

// Holds the handle to the real version.dll from System32
namespace version_proxy {
    inline HMODULE g_version_module = nullptr;

    inline void load() {
        char system_path[MAX_PATH];
        GetSystemDirectoryA(system_path, MAX_PATH);
        strcat_s(system_path, "\\version.dll");
        g_version_module = LoadLibraryA(system_path);
    }

    inline void unload() {
        if (g_version_module) {
            FreeLibrary(g_version_module);
            g_version_module = nullptr;
        }
    }

    inline FARPROC get_proc(const char* name) {
        return g_version_module ? GetProcAddress(g_version_module, name) : nullptr;
    }
}

// Re-export with correct names via linker directives
#pragma comment(linker, "/export:GetFileVersionInfoA=_proxy_GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoByHandle=_proxy_GetFileVersionInfoByHandle")
#pragma comment(linker, "/export:GetFileVersionInfoExA=_proxy_GetFileVersionInfoExA")
#pragma comment(linker, "/export:GetFileVersionInfoExW=_proxy_GetFileVersionInfoExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=_proxy_GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExA=_proxy_GetFileVersionInfoSizeExA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeExW=_proxy_GetFileVersionInfoSizeExW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=_proxy_GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:GetFileVersionInfoW=_proxy_GetFileVersionInfoW")
#pragma comment(linker, "/export:VerFindFileA=_proxy_VerFindFileA")
#pragma comment(linker, "/export:VerFindFileW=_proxy_VerFindFileW")
#pragma comment(linker, "/export:VerInstallFileA=_proxy_VerInstallFileA")
#pragma comment(linker, "/export:VerInstallFileW=_proxy_VerInstallFileW")
#pragma comment(linker, "/export:VerLanguageNameA=_proxy_VerLanguageNameA")
#pragma comment(linker, "/export:VerLanguageNameW=_proxy_VerLanguageNameW")
#pragma comment(linker, "/export:VerQueryValueA=_proxy_VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=_proxy_VerQueryValueW")

// Proxy export stubs - forward every call to the real version.dll
// Prefixed with _proxy_ to avoid conflicts with winver.h declarations
extern "C" {
    BOOL WINAPI _proxy_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoA)>(version_proxy::get_proc("GetFileVersionInfoA"));
        return fn ? fn(a, b, c, d) : FALSE;
    }
    BOOL WINAPI _proxy_GetFileVersionInfoByHandle(DWORD a, HANDLE b, DWORD c, LPVOID d) {
        static auto fn = reinterpret_cast<BOOL(WINAPI*)(DWORD, HANDLE, DWORD, LPVOID)>(version_proxy::get_proc("GetFileVersionInfoByHandle"));
        return fn ? fn(a, b, c, d) : FALSE;
    }
    BOOL WINAPI _proxy_GetFileVersionInfoExA(DWORD a, LPCSTR b, DWORD c, DWORD d, LPVOID e) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoExA)>(version_proxy::get_proc("GetFileVersionInfoExA"));
        return fn ? fn(a, b, c, d, e) : FALSE;
    }
    BOOL WINAPI _proxy_GetFileVersionInfoExW(DWORD a, LPCWSTR b, DWORD c, DWORD d, LPVOID e) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoExW)>(version_proxy::get_proc("GetFileVersionInfoExW"));
        return fn ? fn(a, b, c, d, e) : FALSE;
    }
    DWORD WINAPI _proxy_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoSizeA)>(version_proxy::get_proc("GetFileVersionInfoSizeA"));
        return fn ? fn(a, b) : 0;
    }
    DWORD WINAPI _proxy_GetFileVersionInfoSizeExA(DWORD a, LPCSTR b, LPDWORD c) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoSizeExA)>(version_proxy::get_proc("GetFileVersionInfoSizeExA"));
        return fn ? fn(a, b, c) : 0;
    }
    DWORD WINAPI _proxy_GetFileVersionInfoSizeExW(DWORD a, LPCWSTR b, LPDWORD c) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoSizeExW)>(version_proxy::get_proc("GetFileVersionInfoSizeExW"));
        return fn ? fn(a, b, c) : 0;
    }
    DWORD WINAPI _proxy_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoSizeW)>(version_proxy::get_proc("GetFileVersionInfoSizeW"));
        return fn ? fn(a, b) : 0;
    }
    BOOL WINAPI _proxy_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
        static auto fn = reinterpret_cast<decltype(&::GetFileVersionInfoW)>(version_proxy::get_proc("GetFileVersionInfoW"));
        return fn ? fn(a, b, c, d) : FALSE;
    }
    DWORD WINAPI _proxy_VerFindFileA(DWORD a, LPSTR b, LPSTR c, LPSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h) {
        static auto fn = reinterpret_cast<decltype(&::VerFindFileA)>(version_proxy::get_proc("VerFindFileA"));
        return fn ? fn(a, b, c, d, e, f, g, h) : 0;
    }
    DWORD WINAPI _proxy_VerFindFileW(DWORD a, LPWSTR b, LPWSTR c, LPWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h) {
        static auto fn = reinterpret_cast<decltype(&::VerFindFileW)>(version_proxy::get_proc("VerFindFileW"));
        return fn ? fn(a, b, c, d, e, f, g, h) : 0;
    }
    DWORD WINAPI _proxy_VerInstallFileA(DWORD a, LPSTR b, LPSTR c, LPSTR d, LPSTR e, LPSTR f, LPSTR g, PUINT h) {
        static auto fn = reinterpret_cast<decltype(&::VerInstallFileA)>(version_proxy::get_proc("VerInstallFileA"));
        return fn ? fn(a, b, c, d, e, f, g, h) : 0;
    }
    DWORD WINAPI _proxy_VerInstallFileW(DWORD a, LPWSTR b, LPWSTR c, LPWSTR d, LPWSTR e, LPWSTR f, LPWSTR g, PUINT h) {
        static auto fn = reinterpret_cast<decltype(&::VerInstallFileW)>(version_proxy::get_proc("VerInstallFileW"));
        return fn ? fn(a, b, c, d, e, f, g, h) : 0;
    }
    DWORD WINAPI _proxy_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
        static auto fn = reinterpret_cast<decltype(&::VerLanguageNameA)>(version_proxy::get_proc("VerLanguageNameA"));
        return fn ? fn(a, b, c) : 0;
    }
    DWORD WINAPI _proxy_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
        static auto fn = reinterpret_cast<decltype(&::VerLanguageNameW)>(version_proxy::get_proc("VerLanguageNameW"));
        return fn ? fn(a, b, c) : 0;
    }
    BOOL WINAPI _proxy_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID* c, PUINT d) {
        static auto fn = reinterpret_cast<decltype(&::VerQueryValueA)>(version_proxy::get_proc("VerQueryValueA"));
        return fn ? fn(a, b, c, d) : FALSE;
    }
    BOOL WINAPI _proxy_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d) {
        static auto fn = reinterpret_cast<decltype(&::VerQueryValueW)>(version_proxy::get_proc("VerQueryValueW"));
        return fn ? fn(a, b, c, d) : FALSE;
    }
}