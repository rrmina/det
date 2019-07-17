/*
 *  Prints AHK/scripts' filepath if scanned
 *  Closes if no AHK script/binary is detected
 *  Works for Latest version of AHK v1.1.3
 * 
 *  To compile:
 * 
 *      gcc script_det.c include/fuzzy.c -lpsapi
 * 
 * 
 *  Possible improvements could be:
 *      1. Parallelize FOR loops / if-else in "Get hash and compare signatures"
 *      2. Do only FOR loop of "Get hash and compare signatures" at start 
 *              Afterwards monitor for newly opened/terminated processes
 *      3. Add more signatures
 * 
 *  Problems
 *      1. Different versions of AutoHotkey still have dissimilar fuzzy hashes
 *      2. Scripts using recompiled source are not being listed by EnumProcesses
 *          i.e. This can't detect BombBomb.exe yet because I don't know how to list it from EnumProcesses
 * 
 *  Reference
 *      1. Antivirus Signatures :   http://hooked-on-mnemonics.blogspot.com/2011/01/intro-to-creating-anti-virus-signatures.html
 *      2. Fuzzy Hashing        :   https://github.com/ssdeep-project/ssdeep
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
    "24576:hoNolOhBCfXLEX2kr/KXE9UI7EkJqTC7q2i1:DlOhBCfLUjME9UI7JJqW7Y",                                        // Compiled .ahk -> .exe 64 bit
    "24576:UGf8s3gt9LWhHPY/3rvTg9bXdC8fZULm6F:p8s3gt9LoHwjvTyXdC8fZO",                                          // AutoHotkey.exe 64 bit
    "12288:1m5qA533YfhZ+z5+Qx5CqocApRBxl0vurKUMMvkX/wECYBvuq17VGwBcW9cAgbGn:1m5kL+z5+Qx5CBl0vuzKb9cAq35SGBjC",  // AutoHotkeyA32.exe
    "12288:SLWctC9JiZiCMW4xW23TGfOLqO7AUWTDdKd4LbpANE:SLztC9M74WbOLq+WTDdKd4pAq",                               // AutoHotkeyU32.exe
    "24576:Gkc6XmcjEbSmzUUE3dPMq9rzrJApvDDP+6Gvtx2Z/YCjd6YotC3DLvNGh/:G16Wc4bmNMq9j2pLDLOt0IYowzDNG"            // BombBomb.exe - Recompiled source 64 bit VS2015
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
            // File size of ahk files
            // 1. Autohotkey binary < 1.2mb
            // 2. Compiled .ahk     < 1.2mb
            // 3. Recompiled source < 1.9mb
            // using < 1.2mb condition significantly improves performance 

            long temp_size = (getFileSize(filename));
            //if ((temp_size < 1200000) || ((temp_size > 1800000) && (temp_size < 1900000))) {
            if (temp_size < 1200000) {
                char* result;
                result = (char*) malloc(FUZZY_MAX_RESULT);

                // Get fuzzy hash
                fuzzy_hash_filename(filename, result);
                
                // Compare fuzzy hash to script signatures  -  if greater than 0 then match/script detected
                int count;
                for (count = 0; count < 5; count++) {
                    if (fuzzy_compare(sigs[count], result) > 0) {
                        print(filename);
                        getch();
                    }
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