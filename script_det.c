/*
 *  Prints AHK/scripts' filepath if scanned
 *  Closes if no AHK script/binary is detected
 * 
 *      Reference
 *      1. Antivirus Signatures :   http://hooked-on-mnemonics.blogspot.com/2011/01/intro-to-creating-anti-virus-signatures.html
 *      2. Fuzzy Hashing        :   https://github.com/ssdeep-project/ssdeep
 * 
 *  Possible improvements could be:
 *      1. Parallelize FOR loops / if-else in "Get hash and compare signatures"
 *      2. Do only FOR loop of "Get hash and compare signatures" at start 
 *              Afterwards monitor for newly opened/terminated processes
 *      3. Add more signatures
 * 
 * 
 *  */


#include <windows.h>
#include <psapi.h> // For access to GetModuleFileNameEx
#include <tchar.h>
#include <stdio.h>
#include <conio.h> // For access to getch
#include "include/fuzzy.h"

#define PRINT_FAIL 0

char* sigs[] = {
    "24576:hoNolOhBCfXLEX2kr/KXE9UI7EkJqTC7q2i1:DlOhBCfLUjME9UI7JJqW7Y", // AutoHotkey.exe            64 bit
    "24576:UGf8s3gt9LWhHPY/3rvTg9bXdC8fZULm6F:p8s3gt9LoHwjvTyXdC8fZO",   // Compiled .ahk -> .exe     64 bit

    };

void print(char* a){
    printf("%s\n", a);
}

long getFileSize(char* filename) {
    long nSize = 1000000000;
    WIN32_FILE_ATTRIBUTE_DATA fInfo;

    if(GetFileAttributesEx(filename, 0, &fInfo))
        nSize = fInfo.nFileSizeLow;

    return nSize;
}

void findHashMatch( DWORD processID) {
    HANDLE processHandle = NULL;
    char filename[MAX_PATH];

    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (processHandle != NULL) {
        if (GetModuleFileNameEx(processHandle, NULL, filename, MAX_PATH) == 0) {
            CloseHandle(processHandle);
        }
        else {
            if (getFileSize(filename) < 1200000) {
                char* result;
                result = (char*) malloc(FUZZY_MAX_RESULT);

                // Get fuzzy hash
                fuzzy_hash_filename(filename, result);
                
                // Compare fuzzy hash to script signatures  -  if greater than 0 then match/script detected
                if (fuzzy_compare(sigs[0], result) > 0) {
                    print(filename);
                    getch();
                }
                else if (fuzzy_compare(sigs[1], result) > 0) {
                    print(filename);
                    getch();
                }

                free(result);
            }

            CloseHandle(processHandle);
        }
    } 
#ifndef PRINT_FAIL
    else 
        print("Failed to open process."); 
#endif
}

int main() {

    // Get list of PID
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
        return 1;

    cProcesses = cbNeeded / sizeof(DWORD);

    // Get hash and compare to signatures
    for (i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0)
            findHashMatch(aProcesses[i]);
    }

    return 0;
}