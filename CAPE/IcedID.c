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
#include "..\hooking.h"
#include "..\log.h"
#include "CAPE.h"

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);

extern int GetIcedIDHeader(PVOID Payload);

HOOKDEF(NTSTATUS, WINAPI, RtlDecompressBuffer,
	__in USHORT CompressionFormat,
	__out PUCHAR UncompressedBuffer,
	__in ULONG UncompressedBufferSize,
	__in PUCHAR CompressedBuffer,
	__in ULONG CompressedBufferSize,
	__out PULONG FinalUncompressedSize
) {
	NTSTATUS ret = Old_RtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize,
		CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);

    if (NT_SUCCESS(ret)) {
        DoOutputDebugString("RtlDecompressBuffer hook: scanning region 0x%x size 0x%x for IcedID Bot image.\n", UncompressedBuffer, *FinalUncompressedSize);
		CapeMetaData->DumpType = ICEDID_BOT;
        GetIcedIDHeader(UncompressedBuffer);
        LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
            *FinalUncompressedSize, UncompressedBuffer, "UncompressedBufferLength", *FinalUncompressedSize);
    }
    else
        LOQ_ntstatus("misc", "pch", "UncompressedBufferAddress", UncompressedBuffer, "UncompressedBuffer",
            0, UncompressedBuffer, "UncompressedBufferLength", 0);

    return ret;
}
