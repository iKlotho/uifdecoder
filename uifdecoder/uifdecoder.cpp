#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <filesystem>

HCRYPTPROV hCryptProv = NULL;
HCRYPTKEY hKey = NULL;
HCRYPTHASH hHash = NULL;

void LoadCrypto(BYTE* keyData) {
    if (CryptAcquireContext(&hCryptProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0)) {
        if (CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) {
            if (CryptHashData(hHash, keyData, 29, CRYPT_USERDATA)) {
                if (!CryptDeriveKey(hCryptProv, CALG_RC4, hHash, 0x00800000, &hKey)) {
                    TerminateProcess(GetCurrentProcess(), 0);
                }
            }
        }
    }
}

void CreateOutputDirectory() {  
   std::wstring outputFolder = L"output"; // Use wide string literal for Unicode compatibility  
   if (!CreateDirectory(outputFolder.c_str(), NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {  
       std::cerr << "Error creating output directory.\n";  
       exit(1);  
   }  
}

std::string DecryptFile(const std::string& inputPath) {
    CreateOutputDirectory();  // Ensure output folder exists

    std::string outputPath = "output/" + inputPath.substr(inputPath.find_last_of("\\/") + 1) + ".uif";

    HANDLE hSourceFile = CreateFileA(inputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hDestFile = CreateFileA(outputPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hSourceFile == INVALID_HANDLE_VALUE || hDestFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open files.\n";
        return "";
    }

    LARGE_INTEGER size;
    GetFileSizeEx(hSourceFile, &size);
    LONG len = (size.HighPart << 32) | size.LowPart;
    DWORD dwBlockLen = (len % 2 == 0) ? 32 : 31;

    BYTE* buffer = (BYTE*)malloc(dwBlockLen);
    if (!buffer) {
        std::cerr << "Memory allocation failed.\n";
        return "";
    }

    DWORD bytesRead = 0, bytesWritten = 0;
    // Copy the first 4 bytes as-is
    if (ReadFile(hSourceFile, buffer, 4, &bytesRead, NULL)) {
        WriteFile(hDestFile, buffer, bytesRead, &bytesWritten, NULL);
    }

    ZeroMemory(buffer, dwBlockLen);
    bool eof = false;

    while (!eof) {
        if (ReadFile(hSourceFile, buffer, dwBlockLen, &bytesRead, NULL)) {
            if (bytesRead < dwBlockLen) {
                eof = true;
            }
            DWORD count = bytesRead;
            if (CryptDecrypt(hKey, 0, TRUE, 0, buffer, &count)) {
                WriteFile(hDestFile, buffer, count, &bytesWritten, NULL);
            }
        }
        else {
            break;
        }
    }

    if (buffer) free(buffer);
    if (hSourceFile) CloseHandle(hSourceFile);
    if (hDestFile) CloseHandle(hDestFile);

    std::cout << "Decryption complete: " << inputPath << " -> " << outputPath << std::endl;
    return outputPath;
}

std::string EncryptFile(const std::string& inputPath) {
    CreateOutputDirectory();  // Ensure output folder exists

    std::string outputPath = "output/" + inputPath.substr(inputPath.find_last_of("\\/") + 1) + "_encrypted.uif";

    HANDLE hSourceFile = CreateFileA(inputPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    HANDLE hDestFile = CreateFileA(outputPath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hSourceFile == INVALID_HANDLE_VALUE || hDestFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open files.\n";
        return "";
    }

    LARGE_INTEGER size;
    GetFileSizeEx(hSourceFile, &size);
    LONG len = (size.HighPart << 32) | size.LowPart;
    DWORD dwBlockLen = (len % 2 == 0) ? 32 : 31;

    BYTE* buffer = (BYTE*)malloc(dwBlockLen);
    if (!buffer) {
        std::cerr << "Memory allocation failed.\n";
        return "";
    }

    DWORD bytesRead = 0, bytesWritten = 0;
    // Copy the first 4 bytes as-is
    if (ReadFile(hSourceFile, buffer, 4, &bytesRead, NULL)) {
        WriteFile(hDestFile, buffer, bytesRead, &bytesWritten, NULL);
    }

    ZeroMemory(buffer, dwBlockLen);
    bool eof = false;

    while (!eof) {
        if (ReadFile(hSourceFile, buffer, dwBlockLen, &bytesRead, NULL)) {
            if (bytesRead < dwBlockLen) {
                eof = true;
            }
            DWORD count = bytesRead;
            if (CryptEncrypt(hKey, 0, TRUE, 0, buffer, &count, dwBlockLen)) {
                WriteFile(hDestFile, buffer, count, &bytesWritten, NULL);
            }
        }
        else {
            break;
        }
    }

    if (buffer) free(buffer);
    if (hSourceFile) CloseHandle(hSourceFile);
    if (hDestFile) CloseHandle(hDestFile);

    std::cout << "Encryption complete: " << inputPath << " -> " << outputPath << std::endl;
    return outputPath;
}

void ProcessDirectory(const std::string& directory, bool isEncryption) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            std::string filePath = entry.path().string();
            if (isEncryption) {
                EncryptFile(filePath);
            }
            else {
                DecryptFile(filePath);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: decryptor.exe -e|-d <input_file_or_directory>\n";
        return 1;
    }

    std::string option = argv[1];
    std::string inputPath = argv[2];

    BYTE keyData[] = "(A;dq1DPVFgVs1Aez$VS3R0hge@NvM_TJvblD4.af0h@r4bUzp";
    LoadCrypto(keyData);

    DWORD fileAttr = GetFileAttributesA(inputPath.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES) {
        std::cerr << "Error: Invalid file or directory path.\n";
        return 1;
    }

    bool isDirectory = (fileAttr & FILE_ATTRIBUTE_DIRECTORY) != 0;
    if (isDirectory) {
        ProcessDirectory(inputPath, option == "-e");
    }
    else {
        if (option == "-e") {
            EncryptFile(inputPath);
        }
        else if (option == "-d") {
            DecryptFile(inputPath);
        }
        else {
            std::cerr << "Invalid option. Use -e for encryption or -d for decryption.\n";
            return 1;
        }
    }

    return 0;
}
