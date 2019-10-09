//fallout 76 dupe 2019
//place items in power armor station
//scrap the C.A.M.P workshop object
//tell a friend to take items from power armor station
//drop a item to rollback power armor station inventory
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
using namespace std;
#define list 0x5583548//75 71 48 8B 05 ? ? ? ? 80 B8 03 1A 00 00 00 75 61
bool dupe(HWND hWnd);

//https://stackoverflow.com/a/51731567
static BOOL CALLBACK enumWindowCallback(HWND hWnd, LPARAM lparam) {
    int length = GetWindowTextLength(hWnd);
    char* buffer = new char[length + 1];
    GetWindowText(hWnd, buffer, length + 1);
    if (!strcmp(buffer, "Fallout76")) {
        dupe(hWnd);
    }
    return TRUE;
}

//https://stackoverflow.com/a/26573045
DWORD_PTR GetProcessBaseAddress(DWORD processID)
{
    DWORD_PTR   baseAddress = 0;
    HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HMODULE     *moduleArray;
    LPBYTE      moduleArrayBytes;
    DWORD       bytesRequired;

    if (processHandle)
    {
        if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
        {
            if (bytesRequired)
            {
                moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

                if (moduleArrayBytes)
                {
                    unsigned int moduleCount;

                    moduleCount = bytesRequired / sizeof(HMODULE);
                    moduleArray = (HMODULE *)moduleArrayBytes;

                    if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
                    {
                        baseAddress = (DWORD_PTR)moduleArray[0];
                    }

                    LocalFree(moduleArrayBytes);
                }
            }
        }

        CloseHandle(processHandle);
    }

    return baseAddress;
}

bool dupe(HWND hWnd) {
    DWORD pid;
    GetWindowThreadProcessId(hWnd, &pid);
    if (!pid) return false;
    DWORD_PTR base = GetProcessBaseAddress(pid);
    if (!base) return false;
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, 0, pid);
    if (!h) return false;

    __int64 lists = base + list;
    if (!ReadProcessMemory(h, (PVOID*)lists, &lists, 8, 0)) return false;

    __int64 a_buffer = lists + 0x418;
    if (!ReadProcessMemory(h, (PVOID*)a_buffer, &a_buffer, 8, 0)) return false;

    __int64 a_list[2000];
    if (!ReadProcessMemory(h, (PVOID*)a_buffer, &a_list, 8 * 2000, 0)) return false;

    a_buffer = 0;
    for (size_t i = 0; i < 2000; i += 1) {
        __int32 a_editor;
        a_list[i] += 0x20;
        if (!ReadProcessMemory(h, (PVOID*)a_list[i], &a_editor, 4, 0)) continue;
        if (a_editor != 0x12D065) continue;
        a_list[i] -= 0x20;
        a_buffer = a_list[i];
        break;
    }
    if (!a_buffer) return false;
    a_buffer += 0x20;

    __int64 b_buffer = lists + 0x568;
    if (!ReadProcessMemory(h, (PVOID*)b_buffer, &b_buffer, 8, 0)) return false;

    __int64 b_list[2000];
    if (!ReadProcessMemory(h, (PVOID*)b_buffer, &b_list, 8 * 2000, 0)) return false;

    b_buffer = 0;
    for (size_t i = 0; i < 2000; i += 1) {
        __int32 b_editor;
        b_list[i] += 0x20;
        if (!ReadProcessMemory(h, (PVOID*)b_list[i], &b_editor, 4, 0)) continue;
        if (b_editor != 0x157FEB) continue;
        b_list[i] -= 0x20;
        b_buffer = b_list[i];
        break;
    }
    if (!b_buffer) return false;
    b_buffer += 0x238;

    __int32 a_editor = 0x157FEB;
    if (!WriteProcessMemory(h, (PVOID*)a_buffer, &a_editor, 4, 0)) return false;

    __int8 b_editor = 0;
    if (!WriteProcessMemory(h, (PVOID*)b_buffer, &b_editor, 1, 0)) return false;

    return true;
}

int main() {
    EnumWindows(enumWindowCallback, NULL);
    return 0;
}
