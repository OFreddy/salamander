// SPDX-FileCopyrightText: 2023 Open Salamander Authors
// SPDX-License-Identifier: GPL-2.0-or-later

#include <windows.h>

#include "lstrfix.h"

#pragma warning(3 : 4706) // warning C4706: assignment within conditional expression

static const unsigned char dizzykeymapdec[] = {
	0x3D, 0x67, 0x68, 0x16, 0x2F, 0x18, 0x58, 0x0F, 
	0x74, 0x7E, 0x5F, 0x24, 0x5B, 0x6A, 0x70, 0x1C, 
	0x19, 0x3F, 0x03, 0x59, 0x44, 0x7F, 0x47, 0x15, 
	0x53, 0x62, 0x6F, 0x12, 0x64, 0x3A, 0x1A, 0x10, 
	0x55, 0x42, 0x22, 0x75, 0x2A, 0x48, 0x04, 0x26, 
	0x4E, 0x54, 0x11, 0x2D, 0x3C, 0x57, 0x5A, 0x33, 
	0x0C, 0x0A, 0x3B, 0x37, 0x46, 0x63, 0x30, 0x29, 
	0x4D, 0x40, 0x7D, 0x61, 0x50, 0x7B, 0x7A, 0x1B, 
	0x2C, 0x31, 0x1E, 0x0E, 0x21, 0x06, 0x71, 0x5D, 
	0x35, 0x65, 0x1F, 0x56, 0x3E, 0x08, 0x4F, 0x23, 
	0x07, 0x14, 0x69, 0x38, 0x34, 0x7C, 0x20, 0x6B, 
	0x17, 0x72, 0x0D, 0x45, 0x13, 0x6C, 0x2E, 0x00, 
	0x4B, 0x49, 0x6E, 0x41, 0x5E, 0x32, 0x77, 0x76, 
	0x0B, 0x39, 0x4A, 0x05, 0x27, 0x6D, 0x60, 0x2B, 
	0x52, 0x25, 0x4C, 0x5C, 0x1D, 0x01, 0x73, 0x78, 
	0x79, 0x36, 0x43, 0x09, 0x02, 0x51, 0x66, 0x28
};

static const unsigned char _IsWow64Process[] = {
	0x61, 0x76, 0x2D, 0x1A, 0x66, 0x79, 0x54, 0x3C, 
	0x59, 0x1A, 0x35, 0x49, 0x76, 0x76, 0x00
};

static const unsigned char _SetProcessUserModeExceptionPolicy[] = {
    0x18, 0x49, 0x08, 0x3C, 0x59, 0x1A, 0x35, 0x49,
    0x76, 0x76, 0x20, 0x76, 0x49, 0x59, 0x38, 0x1A,
    0x1C, 0x49, 0x5B, 0x77, 0x35, 0x49, 0x0E, 0x08,
    0x52, 0x1A, 0x62, 0x3C, 0x1A, 0x5D, 0x52, 0x35,
    0x78, 0x00
};

static const unsigned char _GetProcessUserModeExceptionPolicy[] = {
    0x16, 0x49, 0x08, 0x3C, 0x59, 0x1A, 0x35, 0x49,
    0x76, 0x76, 0x20, 0x76, 0x49, 0x59, 0x38, 0x1A,
    0x1C, 0x49, 0x5B, 0x77, 0x35, 0x49, 0x0E, 0x08,
    0x52, 0x1A, 0x62, 0x3C, 0x1A, 0x5D, 0x52, 0x35,
    0x78, 0x00
};

LPCSTR DizzyDecode(LPCSTR src, LPSTR dst)
{
    size_t i;

    for (i = 0; i < strlen(src); i++)
        dst[i] = dizzykeymapdec[src[i]];

    return dst;
}

/*
SALSPAWN errorcodes:
  err -> External prg err
  retBase -> bad options
  retBase + 1 -> no executable
  retBase * 2 + err -> CreateProcess err
  retBase * 3 + err -> WaitForSingleObject err
  retBase * 4 + err -> GetExitCode err
*/

BOOL CtrlHandler(DWORD fdwCtrlType)
{
    switch (fdwCtrlType)
    {
    // vyignorujeme CTRL+C, Ctrl+Break a dalsi dobre duvody pro ukonceni... protoze ukoncit
    // se musi nejdrive spousteny externi archivator (jinak archivator pokracuje ve spousteni,
    // i kdyz uz Salamander pise, ze komprimace/dekomprimace skoncila)
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        return TRUE;

    default:
        return FALSE;
    }
}

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
        FIsWow64Process isWow64 = (FIsWow64Process)GetProcAddress(hDLL, DizzyDecode((LPCSTR)&_IsWow64Process, (LPSTR)&tmp));                                                      // Min: XP SP2
        FSetProcessUserModeExceptionPolicy set = (FSetProcessUserModeExceptionPolicy)GetProcAddress(hDLL, DizzyDecode((LPCSTR)&_SetProcessUserModeExceptionPolicy, (LPSTR)&tmp)); // Min: Vista with hotfix
        FGetProcessUserModeExceptionPolicy get = (FGetProcessUserModeExceptionPolicy)GetProcAddress(hDLL, DizzyDecode((LPCSTR)&_GetProcessUserModeExceptionPolicy, (LPSTR)&tmp)); // Min: Vista with hotfix
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

void mainCRTStartup()
{
    EnableExceptionsOn64();
    SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE);
    BOOL help = FALSE;
    BOOL error = FALSE;
    int retBase = 10000;
    char exeName[1000];
    char* cmdline;
    DWORD exitCode;

    exeName[0] = '\0';

    // nechceme zadne kriticke chyby jako "no disk in drive A:"
    SetErrorMode(SetErrorMode(0) | SEM_FAILCRITICALERRORS);

    cmdline = GetCommandLine();
    // skip leading spaces
    while (*cmdline == ' ' || *cmdline == '\t')
        cmdline++;
    // skip exe name
    if (*cmdline == '"')
    {
        cmdline++;
        while (*cmdline != '\0' && *cmdline != '"')
            cmdline++;
        if (*cmdline == '"')
            cmdline++;
    }
    else
        while (*cmdline != '\0' && *cmdline != ' ' && *cmdline != '\t')
            cmdline++;
    // get params
    while (1)
    {
        // skip spaces
        while (*cmdline == ' ' || *cmdline == '\t')
            cmdline++;
        if (*cmdline == '\0')
            break;
        // is it a switch ?
        if (*cmdline == '-' || *cmdline == '/')
        {
            cmdline += 2;
            switch (*(cmdline - 1))
            {
            case '?':
            case 'h':
            case 'H':
                help = TRUE;
                break;
            case 'c':
                if (*cmdline > '9' || *cmdline < '0')
                {
                    help = TRUE;
                    break;
                }
                retBase = 0;
                while (*cmdline <= '9' && *cmdline >= '0')
                    retBase = retBase * 10 + *cmdline++ - '0';
                if (*cmdline != ' ' && *cmdline != '\t' && *cmdline != '\0')
                {
                    help = TRUE;
                    break;
                }
                break;
            default:
                ExitProcess(retBase);
            }
        }
        // if not, it must be a line to execute
        else
        {
            int len = 0;
            while (len < 1000 && *cmdline != '\0')
                exeName[len++] = *cmdline++;
            exeName[len] = '\0';
        }
    }

    if (exeName[0] == '\0' || help)
    {
        DWORD written;
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE),
                  "SALSPAWN: Spawn for Open Salamander, Copyright (C) 1998-2023 Open Salamander Authors\n\nUsage: salspawn [-|/<switch>] <executable> [exe params]\n\nAvailable switches:\n  ?,h,H - this help screen\n  c<num> - sets base of SALSPAWN error level to <num>\n\n",
                  221, &written, NULL);
        ExitProcess(retBase + 1);
    }

    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    si.cb = sizeof(si);
    si.lpReserved = NULL;
    si.lpTitle = NULL;
    si.lpDesktop = NULL;
    si.cbReserved2 = 0;
    si.lpReserved2 = 0;
    si.dwFlags = 0;
    if (!CreateProcess(NULL, exeName, NULL, NULL, TRUE, CREATE_NEW_PROCESS_GROUP,
                       NULL, NULL, &si, &pi))
    {
        ExitProcess(GetLastError() + retBase * 2);
    }

    if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_FAILED)
    {
        exitCode = GetLastError() + retBase * 3;
        goto EXIT1;
    }

    if (!GetExitCodeProcess(pi.hProcess, &exitCode))
    {
        exitCode = GetLastError() + retBase * 4;
    }
EXIT1:
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    ExitProcess(exitCode);
}
