/*
CAPE - Config And Payload Extraction
Copyright(C) 2015 - 2018 Context Information Security. (kevin.oreilly@contextis.com)

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
#include <stdio.h>
#include <distorm.h>
#include "..\hooking.h"
#include "Debugger.h"
#include "CAPE.h"

#define MAX_INSTRUCTIONS 0x10
#define SINGLE_STEP_LIMIT 0x400  // default unless specified in web ui
#define CHUNKSIZE 0x10 * MAX_INSTRUCTIONS

#define DoClearZeroFlag 1
#define DoSetZeroFlag   2
#define PrintEAX        3

extern void DoOutputDebugString(_In_ LPCTSTR lpOutputString, ...);
extern void DoOutputErrorString(_In_ LPCTSTR lpOutputString, ...);
extern void DebuggerOutput(_In_ LPCTSTR lpOutputString, ...);
extern int DumpModuleInCurrentProcess(LPVOID ModuleBase);
extern int DumpMemory(LPVOID Buffer, SIZE_T Size);
extern char *convert_address_to_dll_name_and_offset(ULONG_PTR addr, unsigned int *offset);
extern BOOL is_in_dll_range(ULONG_PTR addr);
extern DWORD_PTR FileOffsetToVA(DWORD_PTR modBase, DWORD_PTR dwOffset);
extern DWORD_PTR GetEntryPointVA(DWORD_PTR modBase);
extern BOOL ScyllaGetSectionByName(PVOID ImageBase, char* Name, PVOID* SectionData, SIZE_T* SectionSize);
extern PCHAR ScyllaGetExportNameByAddress(PVOID Address, PCHAR* ModuleName);
extern ULONG_PTR g_our_dll_base;

char *ModuleName, *PreviousModuleName;
BOOL BreakpointsSet, FilterTrace, TraceAll;
PVOID ModuleBase, DumpAddress;
SIZE_T DumpSize;
BOOL GetSystemTimeAsFileTimeImported, PayloadMarker, PayloadDumped, TraceRunning;
unsigned int DumpCount, Correction, StepCount, StepLimit, TraceDepthLimit, Action0, Action1, Action2, Action3;
char *Instruction0, *Instruction1, *Instruction2, *Instruction3;
unsigned int Type0, Type1, Type2, Type3;
int StepOverRegister, TraceDepthCount, EntryPointRegister;
CONTEXT LastContext;
SIZE_T LastWriteLength;
CHAR DebuggerBuffer[MAX_PATH];

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo);
BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo);

BOOL DoSetSingleStepMode(int Register, PCONTEXT Context, PVOID Handler)
{
    StepOverRegister = Register;
    return SetSingleStepMode(Context, Trace);
}

BOOL Trace(struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress, CIP;
    BOOL StepOver;
    unsigned int DllRVA;
#ifdef BRANCH_TRACE
    PVOID BranchTarget;
#endif

    TraceRunning = TRUE;

    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif

    if (!is_in_dll_range((ULONG_PTR)CIP) || TraceAll || InsideHook(NULL, CIP) || g_config.trace_into_api[0])
    {
        FilterTrace = FALSE;
        StepCount++;
    }
    else
    {
        FilterTrace = TRUE;
    }

#ifdef _WIN64
    if (!FilterTrace && LastContext.Rip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Rax != ExceptionInfo->ContextRecord->Rax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RAX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rax);

        if (LastContext.Rbx != ExceptionInfo->ContextRecord->Rbx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbx);

        if (LastContext.Rcx != ExceptionInfo->ContextRecord->Rcx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RCX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rcx);

        if (LastContext.Rdx != ExceptionInfo->ContextRecord->Rdx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdx);

        if (LastContext.Rsi != ExceptionInfo->ContextRecord->Rsi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsi);

        if (LastContext.Rdi != ExceptionInfo->ContextRecord->Rdi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdi);

        if (LastContext.Rsp != ExceptionInfo->ContextRecord->Rsp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsp);

        if (LastContext.Rbp != ExceptionInfo->ContextRecord->Rbp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbp);
#else
    if (!FilterTrace && LastContext.Eip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Eax != ExceptionInfo->ContextRecord->Eax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EAX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Eax);

        if (LastContext.Ebx != ExceptionInfo->ContextRecord->Ebx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebx);

        if (LastContext.Ecx != ExceptionInfo->ContextRecord->Ecx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ECX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ecx);

        if (LastContext.Edx != ExceptionInfo->ContextRecord->Edx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edx);

        if (LastContext.Esi != ExceptionInfo->ContextRecord->Esi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esi);

        if (LastContext.Edi != ExceptionInfo->ContextRecord->Edi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edi);

        if (LastContext.Esp != ExceptionInfo->ContextRecord->Esp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esp);

        if (LastContext.Ebp != ExceptionInfo->ContextRecord->Ebp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebp);
#endif

        DebuggerOutput(DebuggerBuffer);
    }

    if (!FilterTrace)
        DebuggerOutput("\n");

    if (StepCount > StepLimit)
    {
        DebuggerOutput("Single-step limit reached (%d), releasing.\n", StepLimit);
        StepCount = 0;
        return TRUE;
    }

    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);
    PCHAR FunctionName;

    if (ModuleName)
    {
        if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
        {
            __try
            {
                FunctionName = ScyllaGetExportNameByAddress(CIP, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing instruction pointer 0x%p.\n", CIP);
            }
            if (FunctionName)
                DebuggerOutput("Break in %s::%s (RVA 0x%x, thread %d)\n", ModuleName, FunctionName, DllRVA, GetCurrentThreadId());
            else
                DebuggerOutput("Break in %s (RVA 0x%x, thread %d)\n", ModuleName, DllRVA, GetCurrentThreadId());
            if (PreviousModuleName)
                free (PreviousModuleName);
            PreviousModuleName = ModuleName;
        }
    }

#ifdef BRANCH_TRACE
    BranchTarget = CIP;
    CIP = (PVOID)ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
    DebuggerOutput("Branch trace hit with EIP 0x%p, BranchTarget 0x%p.\n", CIP, BranchTarget);
#endif
    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
        PCHAR ExportName;
        StepOver = FALSE;

        if (FilterTrace && !TraceAll)
            StepOver = TRUE;
        else if (DecodedInstruction.size > 4 && DecodedInstruction.operands.length && !strncmp(DecodedInstruction.operands.p, "DWORD", 5) && strncmp(DecodedInstruction.operands.p, "DWORD [E", 8))
        {
            PVOID *CallTarget = *(PVOID*)((PUCHAR)CIP + DecodedInstruction.size - 4);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(*CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%x.\n", CallTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", *CallTarget);
        }
        else if (DecodedInstruction.size > 4)
        {
            PVOID CallTarget = (PVOID)((PUCHAR)CIP + (int)*(DWORD*)((PUCHAR)CIP + DecodedInstruction.size - 4) + DecodedInstruction.size);
            __try
            {
                ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("Trace: Error dereferencing CallTarget 0x%x.", CallTarget);
                ExportName = NULL;
            }

            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EAX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rax;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Eax;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "ECX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rcx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ecx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EDX", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rdx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s%-30s", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Edx;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else if (!strncmp(DecodedInstruction.operands.p, "EBP", 3))
        {
#ifdef _WIN64
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Rbp;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%p (%02d) %-20s %-6s%-4s0x%-24p", ExceptionInfo->ContextRecord->Rip, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#else
            PVOID CallTarget = (PVOID)ExceptionInfo->ContextRecord->Ebp;
            ExportName = ScyllaGetExportNameByAddress(CallTarget, NULL);
            if (ExportName)
            {
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", ExportName);
                StepOver = TRUE;
            }
            else
                DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s0x%-28x", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", CallTarget);
#endif
        }
        else
            DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#ifdef BRANCH_TRACE
        if (!FilterTrace)
            TraceDepthCount++;
#else
        if (ExportName)
        {
            for (unsigned int i = 0; i < ARRAYSIZE(g_config.trace_into_api); i++)
            {
                if (!g_config.trace_into_api[i])
                    break;
                if (!stricmp(ExportName, g_config.trace_into_api[i]))
                {
                    StepOver = FALSE;
                    TraceDepthCount--;
                    DebuggerOutput("\nTrace: Stepping into %s\n", ExportName);
                }
            }
        }

        if (((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit && !TraceAll) || (StepOver == TRUE && !TraceAll))
        {
            ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, StepOverRegister, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("Trace: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }

            LastContext = *ExceptionInfo->ContextRecord;

            ClearSingleStepMode(ExceptionInfo->ContextRecord);

            return TRUE;
        }
        else
            TraceDepthCount++;
#endif
    }
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
#ifdef BRANCH_TRACE
        if (!FilterTrace)
            TraceDepthCount--;
#else
        if (!FilterTrace || TraceAll)
            DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
        //if ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit)
        //{
        //    DebuggerOutput("Trace: Stepping out of initial depth, releasing.");
        //
        //    ClearSingleStepMode(ExceptionInfo->ContextRecord);
        //
        //    return TRUE;
        //}

        TraceDepthCount--;
#endif
    }
    else if (!FilterTrace)
#ifdef _WIN64
        DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#else
        DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", (unsigned int)CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);
#endif
    if (Instruction0 && !stricmp(DecodedInstruction.mnemonic.p, Instruction0))
    {
        if (Action0 == DoClearZeroFlag)
        {
            ClearZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("Trace: %s detected, clearing zero flag (action0).\n", Instruction0);
        }
        else if (Action0 == DoSetZeroFlag)
        {
            SetZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("Trace: %s detected, setting zero flag (action0).\n", Instruction0);
        }
#ifndef _WIN64
        else if (Action0 == PrintEAX)
        {
            if (ExceptionInfo->ContextRecord->Eax)
                DebuggerOutput("Trace: Print EAX -> 0x%x.\n", ExceptionInfo->ContextRecord->Eax);
        }
#endif

        Action0 = 0;
    }

    if (Instruction1 && !stricmp(DecodedInstruction.mnemonic.p, Instruction1))
    {
        if (Action1 == DoClearZeroFlag)
        {
            ClearZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("Trace: %s detected, clearing zero flag (action1).\n", Instruction1);
        }
        else if (Action1 == DoSetZeroFlag)
        {
            SetZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("Trace: %s detected, setting zero flag (action1).\n", Instruction1);
        }

        Instruction1 = 0;
    }

    LastContext = *ExceptionInfo->ContextRecord;

    SetSingleStepMode(ExceptionInfo->ContextRecord, Trace);

    TraceRunning = FALSE;

    return TRUE;
}

BOOL BreakpointCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID ReturnAddress, CIP;
    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DllRVA, DecodedInstructionsCount = 0;

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("BreakpointCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("BreakpointCallback executed with NULL thread handle.\n");
		return FALSE;
	}

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif
    if (!is_in_dll_range((ULONG_PTR)CIP) || TraceAll || InsideHook(NULL, CIP))
        FilterTrace = FALSE;
    else
        FilterTrace = TRUE;

#ifdef _WIN64
    if (!FilterTrace && LastContext.Rip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Rax != ExceptionInfo->ContextRecord->Rax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RAX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rax);

        if (LastContext.Rbx != ExceptionInfo->ContextRecord->Rbx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbx);

        if (LastContext.Rcx != ExceptionInfo->ContextRecord->Rcx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RCX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rcx);

        if (LastContext.Rdx != ExceptionInfo->ContextRecord->Rdx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDX=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdx);

        if (LastContext.Rsi != ExceptionInfo->ContextRecord->Rsi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsi);

        if (LastContext.Rdi != ExceptionInfo->ContextRecord->Rdi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RDI=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rdi);

        if (LastContext.Rsp != ExceptionInfo->ContextRecord->Rsp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RSP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rsp);

        if (LastContext.Rbp != ExceptionInfo->ContextRecord->Rbp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s RBP=%#I64x", DebuggerBuffer, ExceptionInfo->ContextRecord->Rbp);
#else
    if (!FilterTrace && LastContext.Eip)
    {
        memset(DebuggerBuffer, 0, MAX_PATH*sizeof(CHAR));

        if (LastContext.Eax != ExceptionInfo->ContextRecord->Eax)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EAX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Eax);

        if (LastContext.Ebx != ExceptionInfo->ContextRecord->Ebx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebx);

        if (LastContext.Ecx != ExceptionInfo->ContextRecord->Ecx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ECX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ecx);

        if (LastContext.Edx != ExceptionInfo->ContextRecord->Edx)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDX=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edx);

        if (LastContext.Esi != ExceptionInfo->ContextRecord->Esi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esi);

        if (LastContext.Edi != ExceptionInfo->ContextRecord->Edi)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EDI=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Edi);

        if (LastContext.Esp != ExceptionInfo->ContextRecord->Esp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s ESP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Esp);

        if (LastContext.Ebp != ExceptionInfo->ContextRecord->Ebp)
            _snprintf_s(DebuggerBuffer, MAX_PATH, _TRUNCATE, "%s EBP=0x%x", DebuggerBuffer, ExceptionInfo->ContextRecord->Ebp);
#endif

        DebuggerOutput(DebuggerBuffer);
    }

    if (!FilterTrace)
        DebuggerOutput("\n");

    ModuleName = convert_address_to_dll_name_and_offset((ULONG_PTR)CIP, &DllRVA);

    if (ModuleName)
    {
        if (!PreviousModuleName || strncmp(ModuleName, PreviousModuleName, strlen(ModuleName)))
        {
            PCHAR FunctionName;

            __try
            {
                FunctionName = ScyllaGetExportNameByAddress(CIP, NULL);
            }
            __except(EXCEPTION_EXECUTE_HANDLER)
            {
                DoOutputDebugString("BreakpointCallback: Error dereferencing instruction pointer 0x%p.\n", CIP);
            }
            if (FunctionName)
                DebuggerOutput("Break in %s::%s (RVA 0x%x, thread %d)\n", ModuleName, FunctionName, DllRVA, GetCurrentThreadId());
            else
                DebuggerOutput("Break in %s (RVA 0x%x, thread %d)\n", ModuleName, DllRVA, GetCurrentThreadId());
            if (PreviousModuleName)
                free (PreviousModuleName);
            PreviousModuleName = ModuleName;
        }
    }

    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);
    if (!FilterTrace)
        DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

    if (!strcmp(DecodedInstruction.mnemonic.p, "CALL"))
    {
#ifdef BRANCH_TRACE
        if (!FilterTrace)
            TraceDepthCount++;
#else
        if ((unsigned int)abs(TraceDepthCount) >= TraceDepthLimit && !TraceAll)
        {
            ReturnAddress = (PVOID)((PUCHAR)CIP + DecodedInstruction.size);
            if (!ContextSetThreadBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo->Register, 0, (BYTE*)ReturnAddress, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("BreakpointCallback: Failed to set breakpoint on return address 0x%p\n", ReturnAddress);
            }

            LastContext = *ExceptionInfo->ContextRecord;

            StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

            return TRUE;
        }
        else if (!FilterTrace)
            TraceDepthCount++;
#endif
}
    else if (!strcmp(DecodedInstruction.mnemonic.p, "RET"))
    {
        //if (TraceDepthCount < 0)
        //{
        //    DebuggerOutput("BreakpointCallback: Stepping out of initial depth, releasing.\n");
        //
        //    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);
        //
        //    return TRUE;
        //}
        //else if (!FilterTrace)
        if (!FilterTrace)
            TraceDepthCount--;
    }

    if (Instruction0 && !stricmp(DecodedInstruction.mnemonic.p, Instruction0))
    {
        if (Action0 == DoClearZeroFlag)
        {
            ClearZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("\nBreakpointCallback: %s detected, clearing zero flag (action0).\n", Instruction0);
        }
        else if (Action0 == DoSetZeroFlag)
        {
            SetZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("\nBreakpointCallback: %s detected, setting zero flag (action0).\n", Instruction0);
        }
#ifndef _WIN64
        else if (Action0 == PrintEAX)
        {
            if (ExceptionInfo->ContextRecord->Eax)
                DebuggerOutput("nBreakpointCallback: Print EAX -> 0x%x.\n", ExceptionInfo->ContextRecord->Eax);
        }
#endif
        else
            DebuggerOutput("nBreakpointCallback: Unrecognised action0! (%d)\n", Action0);

        Action0 = 0;
    }

    if (Instruction1 && !stricmp(DecodedInstruction.mnemonic.p, Instruction1))
    {
        if (Action1 == DoClearZeroFlag)
        {
            ClearZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("\nBreakpointCallback: %s detected, clearing zero flag (action1).\n", Instruction1);
        }
        else if (Action1 == DoSetZeroFlag)
        {
            SetZeroFlag(ExceptionInfo->ContextRecord);
            DebuggerOutput("\nBreakpointCallback: %s detected, setting zero flag (action1).\n", Instruction1);
        }

        Action1 = 0;
    }

    LastContext = *ExceptionInfo->ContextRecord;

    StepOverExecutionBreakpoint(ExceptionInfo->ContextRecord, pBreakpointInfo);

    DoSetSingleStepMode(pBreakpointInfo->Register, ExceptionInfo->ContextRecord, Trace);

    return TRUE;
}

BOOL WriteCallback(PBREAKPOINTINFO pBreakpointInfo, struct _EXCEPTION_POINTERS* ExceptionInfo)
{
	PVOID CIP;
    _DecodeType DecodeType;
    _DecodeResult Result;
    _OffsetType Offset = 0;
    _DecodedInst DecodedInstruction;
    unsigned int DecodedInstructionsCount = 0;
    char OutputBuffer[MAX_PATH] = "";

	if (pBreakpointInfo == NULL)
	{
		DoOutputDebugString("WriteCallback executed with pBreakpointInfo NULL.\n");
		return FALSE;
	}

	if (pBreakpointInfo->ThreadHandle == NULL)
	{
		DoOutputDebugString("WriteCallback executed with NULL thread handle.\n");
		return FALSE;
	}

#ifdef _WIN64
    CIP = (PVOID)ExceptionInfo->ContextRecord->Rip;
    DecodeType = Decode64Bits;
#else
    CIP = (PVOID)ExceptionInfo->ContextRecord->Eip;
    DecodeType = Decode32Bits;
#endif

    Result = distorm_decode(Offset, (const unsigned char*)CIP, CHUNKSIZE, DecodeType, &DecodedInstruction, 1, &DecodedInstructionsCount);

    DebuggerOutput("0x%x (%02d) %-20s %-6s%-4s%-30s", CIP, DecodedInstruction.size, (char*)DecodedInstruction.instructionHex.p, (char*)DecodedInstruction.mnemonic.p, DecodedInstruction.operands.length != 0 ? " " : "", (char*)DecodedInstruction.operands.p);

    return TRUE;
}

BOOL BreakpointOnReturn(PVOID Address)
{
    unsigned int Register;
    if (!SetNextAvailableBreakpoint(GetCurrentThreadId(), &Register, 0, Address, BP_EXEC, BreakpointCallback))
    {
        DoOutputDebugString("BreakpointOnReturn: failed to set breakpoint.\n");
        return FALSE;
    }
    strncpy(g_config.break_on_return, "\0", 2);
    DoOutputDebugString("BreakpointOnReturn: breakpoint set with register %d.", Register);
    return TRUE;
}

BOOL SetInitialBreakpoints(PVOID ImageBase)
{
    DWORD_PTR BreakpointVA;
    DWORD Register;

    StepCount = 0;
    TraceDepthCount = 0;

    TraceAll = g_config.trace_all;

    if (!StepLimit)
        StepLimit = SINGLE_STEP_LIMIT;

	if (!bp0 && !bp1 && !bp2 && !bp3 && !bpw0 && !bpw1 && !bpw2 && !bpw3 && !EntryPointRegister && strlen(g_config.break_on_return) < 1)
	{
		DoOutputDebugString("SetInitialBreakpoints: No address specified for Trace breakpoints, defaulting to bp0 on entry point.\n");
		EntryPointRegister = 1;
	}

#ifdef STANDALONE
    TraceDepthLimit = 5;
#endif
    if (!ImageBase)
    {
        ImageBase = GetModuleHandle(NULL);
        DoOutputDebugString("SetInitialBreakpoints: ImageBase not set by base-on-api parameter, defaulting to process image base 0x%p.\n", ImageBase);
		return FALSE;
    }
    else
        DoOutputDebugString("SetInitialBreakpoints: ImageBase set to 0x%p.\n", ImageBase);

    if (EntryPointRegister)
    {
        PVOID EntryPoint = (PVOID)GetEntryPointVA((DWORD_PTR)ImageBase);

        if (EntryPoint)
        {
            Register = EntryPointRegister - 1;

            if (SetBreakpoint(Register, 0, (BYTE*)EntryPoint, BP_EXEC, BreakpointCallback))
            {
                DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on entry point at 0x%p.\n", Register, EntryPoint);
                BreakpointsSet = TRUE;
                bp0 = EntryPoint;
            }
            else
            {
                DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint on entry point failed.\n");
                BreakpointsSet = FALSE;
                return FALSE;
            }
        }
    }
    else if (bp0)
    {
        Register = 0;
        PVOID Callback;

        if ((SIZE_T)bp0 > 0x10000)
            BreakpointVA = (DWORD_PTR)bp0;
        else
            BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp0;

        if (!Type0)
        {
            Type0 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type0 == BP_WRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type0, Callback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp0, Type0);
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (bp1)
    {
        Register = 1;
        PVOID Callback;

        if ((SIZE_T)bp1 > 0x10000)
            BreakpointVA = (DWORD_PTR)bp1;
        else
            BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp1;

        if (!Type1)
        {
            Type1 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type1 == BP_WRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type1, Callback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp1, Type1);
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (bp2)
    {
        Register = 2;
        PVOID Callback;

        if ((SIZE_T)bp2 > 0x10000)
            BreakpointVA = (DWORD_PTR)bp2;
        else
            BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp2;

        if (!Type2)
        {
            Type1 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type2 == BP_WRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type2, Callback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp2, Type2);
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    if (bp3)
    {
        Register = 3;
        PVOID Callback;

        if ((SIZE_T)bp3 > 0x10000)
            BreakpointVA = (DWORD_PTR)bp3;
        else
            BreakpointVA = (DWORD_PTR)ImageBase + (DWORD_PTR)bp3;

        if (!Type3)
        {
            Type1 = BP_EXEC;
            Callback = BreakpointCallback;
        }
        else if (Type3 == BP_WRITE)
            Callback = WriteCallback;

        if (SetBreakpoint(Register, 0, (BYTE*)BreakpointVA, Type3, Callback))
        {
            DoOutputDebugString("SetInitialBreakpoints: Breakpoint %d set on address 0x%p (RVA 0x%x, type %d)\n", Register, BreakpointVA, bp3, Type3);
            BreakpointsSet = TRUE;
        }
        else
        {
            DoOutputDebugString("SetInitialBreakpoints: SetBreakpoint failed for breakpoint %d.\n", Register);
            BreakpointsSet = FALSE;
            return FALSE;
        }
    }

    return BreakpointsSet;
}
