﻿// SPDX-FileCopyrightText: 2023 Open Salamander Authors
// SPDX-License-Identifier: GPL-2.0-or-later

#include "precomp.h"

// modul MS_INIT zajistuje volani konstruktoru statickych objektu ve spravnem poradi
// a na urovni "lib" (pred "user")

#pragma warning(3 : 4706) // warning C4706: assignment within conditional expression

#pragma warning(disable : 4073)
#pragma init_seg(lib)

static const unsigned char _IsWow64Process[] = {
    0x13, 0x29, 0x0D, 0x35, 0x2D, 0x6C, 0x6E, 0x0A,
    0x28, 0x35, 0x39, 0x3F, 0x29, 0x29, 0x00};

static const unsigned char _SetProcessUserModeExceptionPolicy[] = {
    0x09, 0x3F, 0x2E, 0x0A, 0x28, 0x35, 0x39, 0x3F,
    0x29, 0x29, 0x0F, 0x29, 0x3F, 0x28, 0x17, 0x35,
    0x3E, 0x3F, 0x1F, 0x22, 0x39, 0x3F, 0x2A, 0x2E,
    0x33, 0x35, 0x34, 0x0A, 0x35, 0x36, 0x33, 0x39,
    0x23, 0x00};

static const unsigned char _GetProcessUserModeExceptionPolicy[] = {
    0x1D, 0x3F, 0x2E, 0x0A, 0x28, 0x35, 0x39, 0x3F,
    0x29, 0x29, 0x0F, 0x29, 0x3F, 0x28, 0x17, 0x35,
    0x3E, 0x3F, 0x1F, 0x22, 0x39, 0x3F, 0x2A, 0x2E,
    0x33, 0x35, 0x34, 0x0A, 0x35, 0x36, 0x33, 0x39,
    0x23, 0x00};

static LPSTR xorit(LPCSTR in, LPSTR out, int key)
{
    while (*in != 0x00)
    {
        *out = *in ^ key;
        out++;
        in++;
    }
    *out = 0x00;
    return out;
}

class C__MSInit
{
public:
    C__MSInit();
};

C__MSInit __MSInit;

#ifdef HANDLES_ENABLE
void Initialize__Handles();
#endif // HANDLES_ENABLE

#if defined(_DEBUG) && !defined(HEAP_DISABLE)
void Initialize__Heap();
#endif // defined(_DEBUG) && !defined(HEAP_DISABLE)

#ifndef ALLOCHAN_DISABLE
void Initialize__Allochan();
#endif // ALLOCHAN_DISABLE

#ifndef MESSAGES_DISABLE
void Initialize__Messages();
#endif // MESSAGES_DISABLE

#ifndef STR_DISABLE
void Initialize__Str();
#endif // STR_DISABLE

#ifdef TRACE_ENABLE
void Initialize__Trace();
#endif // TRACE_ENABLE

// ****************************************************************************
// EnableExceptionsOn64
//

// Chceme se dozvedet o SEH Exceptions i na x64 Windows 7 SP1 a dal
// http://blog.paulbetts.org/index.php/2010/07/20/the-case-of-the-disappearing-onload-exception-user-mode-callback-exceptions-in-x64/
// http://connect.microsoft.com/VisualStudio/feedback/details/550944/hardware-exceptions-on-x64-machines-are-silently-caught-in-wndproc-messages
// http://support.microsoft.com/kb/976038
void EnableExceptionsOn64()
{
    typedef BOOL(WINAPI * FSetProcessUserModeExceptionPolicy)(DWORD dwFlags);
    typedef BOOL(WINAPI * FGetProcessUserModeExceptionPolicy)(LPDWORD dwFlags);
    typedef BOOL(WINAPI * FIsWow64Process)(HANDLE, PBOOL);
    char tmp[64]{};
#define PROCESS_CALLBACK_FILTER_ENABLED 0x1

    HINSTANCE hDLL = LoadLibrary("KERNEL32.DLL");
    if (hDLL != NULL)
    {
        FIsWow64Process isWow64 = (FIsWow64Process)GetProcAddress(hDLL, xorit((LPSTR)&_IsWow64Process, (LPSTR)&tmp, 0x5A));                                                      // Min: XP SP2
        FSetProcessUserModeExceptionPolicy set = (FSetProcessUserModeExceptionPolicy)GetProcAddress(hDLL, xorit((LPSTR)&_SetProcessUserModeExceptionPolicy, (LPSTR)&tmp, 0x5A)); // Min: Vista with hotfix
        FGetProcessUserModeExceptionPolicy get = (FGetProcessUserModeExceptionPolicy)GetProcAddress(hDLL, xorit((LPSTR)&_GetProcessUserModeExceptionPolicy, (LPSTR)&tmp, 0x5A)); // Min: Vista with hotfix
        if (isWow64 != NULL && set != NULL && get != NULL)
        {
            BOOL bIsWow64;
            if (isWow64(GetCurrentProcess(), &bIsWow64) && bIsWow64)
            {
                DWORD dwFlags;
                if (get(&dwFlags))
                    set(dwFlags & ~PROCESS_CALLBACK_FILTER_ENABLED);
            }
        }
        FreeLibrary(hDLL);
    }
}

C__MSInit::C__MSInit()
{
    EnableExceptionsOn64();
    //  _CrtSetBreakAlloc(77);

#ifdef TRACE_ENABLE
    Initialize__Trace(); // trace.cpp
#endif                   // TRACE_ENABLE
#ifndef MESSAGES_DISABLE
    Initialize__Messages(); // messages.cpp
#endif                      // MESSAGES_DISABLE
#if defined(_DEBUG) && !defined(HEAP_DISABLE)
    Initialize__Heap(); // heap.cpp
#endif                  // defined(_DEBUG) && !defined(HEAP_DISABLE)
#ifndef ALLOCHAN_DISABLE
    Initialize__Allochan(); // allochan.cpp
#endif                      // ALLOCHAN_DISABLE
#ifndef STR_DISABLE
    Initialize__Str(); // str.cpp
#endif                 // STR_DISABLE
#ifdef HANDLES_ENABLE
    Initialize__Handles(); // handles.cpp
#endif                     // HANDLES_ENABLE
}
