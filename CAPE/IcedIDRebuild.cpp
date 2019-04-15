/*
CAPE - Config And Payload Extraction
Copyright(C) 2019 Kevin O'Reilly

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.
*/
#include "Scylla\PeParser.h"
#include "Scylla\ProcessAccessHelp.h"
#include "Scylla\NativeWinApi.h"

typedef struct _ICEDID_BOT_HEADER {
    DWORD   Unknown;
    DWORD   Empty;
    DWORD   VirtualSizeOfImage;
    DWORD   RtlExitUserProcessHook;
    DWORD   PointerToImageBase;
    DWORD   ImportsPointer;
    DWORD   Buffer;
    DWORD   SizeOfBuffer;
    DWORD   NumberOfSections;
} ICEDID_BOT_HEADER, *PICEDID_BOT_HEADER;

#pragma pack(1)
typedef struct _ICEDID_SECTION_HEADER {
    DWORD   VirtualAddress;
    DWORD   VirtualSize;
    DWORD   PointerToRawData;
    DWORD   SizeOfRawData;
    BYTE    Characteristics;
} ICEDID_SECTION_HEADER, *PICEDID_SECTION_HEADER;

PICEDID_BOT_HEADER IcedIDBotHeader;
PICEDID_SECTION_HEADER IcedIDSectionHeaders;
PeParser *IcedPE = 0;

extern "C" void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern "C" void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern "C" int GetIcedIDHeader(PVOID Payload)
{
	SIZE_T HeadersSize;
	DWORD_PTR entrypoint = NULL;
    PBYTE PEHeader;

	NativeWinApi::initialize();
	ProcessAccessHelp::ownModuleList.clear();
	ProcessAccessHelp::setCurrentProcessAsTarget();
	ProcessAccessHelp::getProcessModules(GetCurrentProcess(), ProcessAccessHelp::ownModuleList);

    IcedIDBotHeader = (PICEDID_BOT_HEADER)calloc(1, sizeof(ICEDID_BOT_HEADER));
    if (!IcedIDBotHeader)
        return 0;
    memcpy(IcedIDBotHeader, Payload, sizeof(ICEDID_BOT_HEADER));

    DoOutputDebugString("IcedID Header: %d sections, VirtualSizeOfImage 0x%x, RtlExitUserProcessHook 0x%x, PointerToImageBase 0x%x, ImportsPointer 0x%x, Buffer 0x%x, SizeOfBuffer 0x%x\n", IcedIDBotHeader->NumberOfSections, IcedIDBotHeader->VirtualSizeOfImage, IcedIDBotHeader->RtlExitUserProcessHook, IcedIDBotHeader->PointerToImageBase, IcedIDBotHeader->ImportsPointer, IcedIDBotHeader->Buffer, IcedIDBotHeader->SizeOfBuffer);

    HeadersSize = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS32) + IcedIDBotHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    PEHeader = (BYTE*)calloc(HeadersSize, sizeof(BYTE));
    if (!PEHeader)
        return 0;
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)PEHeader;

    pDosHeader->e_magic = IMAGE_DOS_SIGNATURE;
    pDosHeader->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(PEHeader + pDosHeader->e_lfanew);
    pNtHeader->Signature = IMAGE_NT_SIGNATURE;
    pNtHeader->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    pNtHeader->FileHeader.NumberOfSections = (WORD)IcedIDBotHeader->NumberOfSections;
    pNtHeader->FileHeader.SizeOfOptionalHeader = 0xe0;
    pNtHeader->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
    pNtHeader->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    pNtHeader->OptionalHeader.MajorLinkerVersion = 0xa;
    //pNtHeader->OptionalHeader.SizeOfCode;
    //pNtHeader->OptionalHeader.SizeOfInitializedData;
    //pNtHeader->OptionalHeader.SizeOfUninitializedData;
    pNtHeader->OptionalHeader.AddressOfEntryPoint = IcedIDBotHeader->RtlExitUserProcessHook;
    //pNtHeader->OptionalHeader.BaseOfCode;
    //pNtHeader->OptionalHeader.BaseOfData;
    pNtHeader->OptionalHeader.ImageBase = 0x400000;
    pNtHeader->OptionalHeader.SectionAlignment = 0x1000;
    pNtHeader->OptionalHeader.FileAlignment = 0x200;
    pNtHeader->OptionalHeader.MajorOperatingSystemVersion = 5;
    pNtHeader->OptionalHeader.MinorOperatingSystemVersion = 1;
    pNtHeader->OptionalHeader.MajorSubsystemVersion = 5;
    pNtHeader->OptionalHeader.MinorSubsystemVersion = 1;
    pNtHeader->OptionalHeader.SizeOfImage = IcedIDBotHeader->VirtualSizeOfImage;
    pNtHeader->OptionalHeader.SizeOfHeaders = 0x400;
    //pNtHeader->OptionalHeader.CheckSum;
    pNtHeader->OptionalHeader.Subsystem = 2;
    pNtHeader->OptionalHeader.DllCharacteristics = 0x8140;
    pNtHeader->OptionalHeader.SizeOfStackReserve = 0x100000;
    pNtHeader->OptionalHeader.SizeOfStackCommit = 0x1000;
    pNtHeader->OptionalHeader.SizeOfHeapReserve = 0x100000;
    pNtHeader->OptionalHeader.SizeOfHeapCommit = 0x1000;
    pNtHeader->OptionalHeader.NumberOfRvaAndSizes = 0x10;

    pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IcedIDBotHeader->ImportsPointer;

    IcedPE = new PeParser((PCHAR)PEHeader, FALSE);
    IcedPE->getDosAndNtHeader(PEHeader, HeadersSize);

    IcedIDSectionHeaders = (PICEDID_SECTION_HEADER)calloc(IcedIDBotHeader->NumberOfSections, sizeof(ICEDID_SECTION_HEADER));
    memcpy(IcedIDSectionHeaders, (PVOID)((PBYTE)Payload + sizeof(ICEDID_BOT_HEADER)), IcedIDBotHeader->NumberOfSections*sizeof(ICEDID_SECTION_HEADER));

    return 1;
}

extern "C" void DumpIcedIDPayload(PVOID Payload, SIZE_T NumberOfBytesToWrite)
{
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(IcedPE->pNTHeader32);
	PeFileSection peFileSection;

	if (!IcedIDBotHeader || NumberOfBytesToWrite != IcedIDBotHeader->VirtualSizeOfImage || !IcedIDBotHeader->NumberOfSections)
        return;

    IcedPE->listPeSection.clear();
	IcedPE->listPeSection.reserve(IcedIDBotHeader->NumberOfSections);

	for (DWORD i = 0; i < IcedIDBotHeader->NumberOfSections; i++)
	{
		memset(&peFileSection.sectionHeader, 0, sizeof(IMAGE_SECTION_HEADER));
        peFileSection.sectionHeader.Misc.VirtualSize = IcedPE->alignValue(IcedIDSectionHeaders->VirtualSize, IcedPE->pNTHeader32->OptionalHeader.SectionAlignment);
        peFileSection.sectionHeader.VirtualAddress = IcedIDSectionHeaders->VirtualAddress;
        peFileSection.sectionHeader.SizeOfRawData = IcedIDSectionHeaders->SizeOfRawData;
        peFileSection.sectionHeader.PointerToRawData = IcedIDSectionHeaders->PointerToRawData;
        peFileSection.sectionHeader.Characteristics = IcedIDSectionHeaders->Characteristics;

        DoOutputDebugString("DumpIcedIDPayload: Section %d, virtual size 0x%x, va 0x%p, raw size 0x%x, raw pointer 0x%p.\n", i, IcedIDSectionHeaders->VirtualSize, IcedIDSectionHeaders->VirtualAddress, IcedIDSectionHeaders->SizeOfRawData, IcedIDSectionHeaders->PointerToRawData);
		IcedPE->listPeSection.push_back(peFileSection);
        IcedIDSectionHeaders++;
        pSection++;
	}

    if (IcedPE->dumpProcess((DWORD_PTR)Payload, 0, NULL))
        DoOutputDebugString("DumpIcedIDPayload: IcedID Bot payload dumped, size 0x%x.\n", IcedPE->dumpSize);

    delete IcedPE;

    return;
}