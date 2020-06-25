/*
 * process tracer using intel pin tool
 *  trace process execution state by instruction dumping CPU context and memory access
 *  and few other utilty function
 *
 *  (c) krishs.patil@gmail.com  
*/

#include "pin.H"
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <iomanip>
#include <map>
#include <string>
#include <algorithm>
#include <iterator>
#include <stdarg.h>

#include  "proctracer.h"

using namespace std;

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */
std::ofstream lstream;

PIN_LOCK lock;

ADDRINT modStartAddr, 
        modEndAddr;

TraceFilterRange traceRanges;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */
KNOB<string>    KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace-full-info.txt", "specify trace file name");
KNOB<BOOL>      KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "enable if you want to trace instructions");
KNOB<BOOL>      KnobTraceBasicBlocks(KNOB_MODE_WRITEONCE, "pintool", "b", "0", "enable if you want to log basic block trace");
KNOB<BOOL>      KnobTraceFunctionCalls(KNOB_MODE_WRITEONCE, "pintool", "c", "0", "enable if you want to trace function calls");
KNOB<BOOL>      KnobTraceThreads(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "enable if you want to trace threads activities");
KNOB<BOOL>      KnobTraceModules(KNOB_MODE_WRITEONCE, "pintool", "m", "0", "enable if you want to trace module load/unload activity");
KNOB<BOOL>      KnobEnableSyscallsTrace(KNOB_MODE_WRITEONCE, "pintool", "syscalls", "0", "enable if you want to trace syscalls");
KNOB<BOOL>      KnobEnableHexDump(KNOB_MODE_WRITEONCE, "pintool", "hx", "0", "enable if you want to have hex dump of the memory");
KNOB<string>    KnobFilterModule(KNOB_MODE_WRITEONCE, "pintool", "fm", "main", "filter module to trace, default is main executable");
KNOB<string>    KnobFilterOffsets(KNOB_MODE_WRITEONCE, "pintool", "fo", "", "comma separated list of filter offsets relative to filter module in form of 0x100-0x200,...");


INT32 Usage()
{
    cerr << "Program Tracer" << endl;
    cerr << "trace progra executaion with (module load/unload, basic blocks/instruction level/ memroy read/write support/ thread / calls logs" << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

BOOL IsAddressInTraceRange(ADDRINT address)
{
    if (traceRanges.empty())
        return (address >= modStartAddr && address <= modEndAddr);
    else {
        TraceFilterRange::const_iterator rangeItr = traceRanges.begin();
        for (; rangeItr != traceRanges.end(); rangeItr++) {
            if (address >= rangeItr->first && address <= rangeItr->second)
                return TRUE;
        }
    }
    return FALSE;
}

std::vector<string> SplitString(std::string str, char seperator)
{
    vector<string> strings;
    istringstream iss(str);
    string s;
    while (getline(iss, s, seperator))
        strings.push_back(s);
    return strings;
}

VOID PrintCpuContext(CONTEXT *ctx, string *disass, BOOL all=FALSE)
{
    if (all) {
        lstream << right << std::setw(30) << "\nCPU Context:";
        for (int i = 0; AllContextRegs[i].name[0]; i++) {
            if (i % 4 == 0) {
                lstream << std::endl << std::setw(30);
            }
			lstream << AllContextRegs[i].alias << "=" 
				<< "0x" << std::hex << PIN_GetContextReg(ctx, AllContextRegs[i].ref) << " ";
        }
    } else {
        if (disass->find("call") != string::npos)
            return;
        /*
        print only registers referenced by current instrution by looking at disassembly
        */
        for (int i = 0; AllContextRegs[i].name[0]; i++) {
            for (int j = 0; j < MAX_REG_PARTS; j++) {
                if (AllContextRegs[i].name[j] == nullptr) 
					break;
                if (disass->find(AllContextRegs[i].name[j]) != string::npos) {
					lstream << AllContextRegs[i].alias << "=" 
								<< "0x" << std::hex << PIN_GetContextReg(ctx, AllContextRegs[i].ref) << " ";
                    break;
                }
            }
        }
    }

#if defined(__x86_64__) || defined(_M_X64)
    lstream << "flags=0x" << std::hex << PIN_GetContextReg(ctx, LEVEL_BASE::REG_RFLAGS);
#else
    lstream << "flags=0x" << std::hex << PIN_GetContextReg(ctx, LEVEL_BASE::REG_EFLAGS);
#endif
}

VOID DumpMemory(ADDRINT addr)
{
    const UINT32 size = 64;

    UINT8 memdump[size] = { 0 };

    //PIN_GetLock(&lock, addr);
    size_t n = PIN_SafeCopy(memdump, (void *)addr, size);
    if (n < size) {
        //PIN_ReleaseLock(&lock);
        return;
    }

    char buff[17];
    size_t i = 0;

    lstream << std::hex;

    for (i = 0; i < size; i++) {
        if ((i % 16) == 0) {
            if (i != 0) {
                lstream << "  " << buff << std::endl;
            }
            lstream << std::setfill(' ') << 
                    std::setw(70) << "  0x" << std::setw(16) << std::setfill('0') 
                    << static_cast<unsigned int>(addr+i);
        }
        lstream << " " << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(memdump[i]);
        if ((memdump[i] < 0x20) || (memdump[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = memdump[i];
        buff[(i % 16) + 1] = '\0';
    }
    while ((i % 16) != 0) {
        lstream << "   ";
        i++;
    }
    lstream << "  " << buff << std::setfill(' ') << std::endl;

    //PIN_ReleaseLock(&lock);
}

VOID PrintInstruction(THREADID tid, ADDRINT ip, string *disass, CONTEXT *ctx, INT32 size)
{
    UINT8 v[32];

    if ((size_t)size > sizeof(v))
        return;

    PIN_GetLock(&lock, ip);

	lstream << "tid#" << tid << ": module+0x" << std::hex << ip-modStartAddr << "| ";

    CHAR  opcode[128] = { 0 };
    PIN_SafeCopy(v, (void *)ip, size);
    for (INT32 i = 0; i < size; i++)
        sprintf((char*)opcode + i * 3, "%02x ", v[i]);
    lstream << left << std::setw(25) << opcode;
    lstream << left << std::setw(30) << *disass;  

    PrintCpuContext(ctx, disass);
    lstream << std::endl;

    PIN_ReleaseLock(&lock);
}

static VOID PrintMemoryAccess(THREADID tid, ADDRINT ip, CHAR r, ADDRINT addr, UINT8* memdump, INT32 size, BOOL isPrefetch)
{
    string opstr = r == 'R' ? "Read" : "Write";
	lstream << right << std::setw(70) << opstr << " in thread#" << tid 
        << " from loc 0x" << std::hex << ip 
        << " on addr 0x" << addr << " of " << size << " bytes, "; 

    if (!isPrefetch) {
        switch (size) {
        case 0:
            break;
        case 1:
            lstream << "value=0x" << std::hex << *(INT32*)memdump;
            break;
        case 2:
		lstream << "value=0x" << std::hex << *(INT16*)memdump;
            break;
        case 4:
		lstream << "value=0x" << std::hex << *(INT32*)memdump;
            break;
        case 8:
				lstream << "value=0x" << std::hex << *(INT64*)memdump;
            break;
        default:
            lstream << "value=" << std::hex;
            for (INT32 i = 0; i < size; i++)
                lstream << memdump[i];
            break;
        }
    }
    lstream << std::endl;

    if (KnobEnableHexDump.Value())
        DumpMemory(addr);
}

static VOID OnMemoryAccess(THREADID tid, ADDRINT ip, CHAR r, ADDRINT addr, INT32 size, BOOL isPrefetch)
{
    UINT8 memdump[64] = { 0 };
    PIN_GetLock(&lock, ip);
    if ((size_t)size > sizeof(memdump)) {
        PIN_ReleaseLock(&lock);
        return;
    }
    PIN_SafeCopy(memdump, (void *)addr, size);

    if (1) {
        PrintMemoryAccess(tid, ip, r, addr, memdump, size, isPrefetch);
    }

    PIN_ReleaseLock(&lock);
}

static ADDRINT WriteAddr;
static INT32 WriteSize;

static VOID RecordWriteAddrSize(ADDRINT addr, INT32 size)
{
    WriteAddr = addr;
    WriteSize = size;
}

static VOID OnMemoryAccessWrite(THREADID tid, ADDRINT ip)
{
    OnMemoryAccess(tid, ip, 'W', WriteAddr, WriteSize, false);
}

/* ================================================================================= */
/* This is called for each instruction                                               */
/* ================================================================================= */
VOID OnInstruction(INS ins, VOID *v)
{
    if (IsAddressInTraceRange(INS_Address(ins))) {
        if (INS_IsMemoryRead(ins))
            INS_InsertPredicatedCall( ins, IPOINT_BEFORE, (AFUNPTR)OnMemoryAccess, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, 'R',
                                      IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, INS_IsPrefetch(ins), IARG_END);

        if (INS_HasMemoryRead2(ins))
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)OnMemoryAccess, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, 'R',
                                     IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_BOOL, INS_IsPrefetch(ins), IARG_END);

        if (INS_IsMemoryWrite(ins)) {
            INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)RecordWriteAddrSize, IARG_MEMORYWRITE_EA,
                                     IARG_MEMORYWRITE_SIZE, IARG_END);

            if (INS_HasFallThrough(ins))
                INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)OnMemoryAccessWrite, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);

            if (INS_IsValidForIpointTakenBranch(ins)) 
                INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)OnMemoryAccessWrite, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
        }

        string* disass = new string(INS_Disassemble(ins));
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintInstruction,IARG_THREAD_ID, IARG_INST_PTR, IARG_PTR, disass, IARG_CONTEXT,
                       IARG_UINT32, INS_Size(ins), IARG_END);
    }
}

VOID MakeTraceRangeFilters()
{
    string filterOffsets = KnobFilterOffsets.Value();
    if (!filterOffsets.empty()) {
        std::vector<string> offsets = SplitString(filterOffsets, ',');
        for (std::vector<string>::const_iterator tok = offsets.begin(); tok != offsets.end(); tok++) {
            std::vector<string> range = SplitString(*tok, '-');
            if (range.size() == 2) {
                traceRanges.push_back(
                    std::make_pair<ADDRINT, ADDRINT>(strtoul(range[0].c_str(), 0, 16) + modStartAddr,
                                                     strtoul(range[1].c_str(), 0, 16) + modStartAddr));
            }
        }
    }
}

void OnImageLoad(IMG Img, void *v)
{
    PIN_GetLock(&lock, 0);

    if (KnobTraceModules.Value())
		lstream << "* module loaded - " << IMG_Name(Img) << " " << std::hex << IMG_LowAddress(Img) <<
			":" << std::hex <<  IMG_HighAddress(Img) << std::endl;

    if (KnobFilterModule.Value() == "main") {
        if (IMG_IsMainExecutable(Img)) {
            modStartAddr = IMG_LowAddress(Img), modEndAddr = IMG_HighAddress(Img);
            MakeTraceRangeFilters();
        }
    } else {
        if (IMG_Name(Img).find(KnobFilterModule.Value().c_str()) != string::npos) {
            modStartAddr = IMG_LowAddress(Img), modEndAddr = IMG_HighAddress(Img);
            MakeTraceRangeFilters();
        }
    }

    PIN_ReleaseLock(&lock);
}

void OnImageUnload(IMG Img, void *v)
{
    //TODO: when tracing shared libraries, if traced library gets unloaded, remove filters
    if (KnobTraceModules.Value())
		lstream << "* module unloaded - " << IMG_Name(Img) << " " << std::hex << IMG_LowAddress(Img) <<
			":" << std::hex <<  IMG_HighAddress(Img) << std::endl;
}


void OnBasicBlock(THREADID tid, ADDRINT addr, UINT32 size, CONTEXT* context)
{
    PIN_GetLock(&lock, addr);
    string name = RTN_FindNameByAddress(addr);
    lstream << "\nbasic block in #thread" <<  tid << " 0x" << std::hex << addr << " of size "  << size;

    if (!name.empty())
		lstream << " (" << name << ")";

    PrintCpuContext(context, 0, TRUE);
    lstream << std::endl;

    PIN_ReleaseLock(&lock);
}

void LogCallAndArgs(THREADID tid, ADDRINT ip, ADDRINT target, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
    string nameFunc = RTN_FindNameByAddress(target);

    PIN_GetLock(&lock, ip);
	lstream << " > call in thread#" << tid 
        << " from: 0x" <<std::hex << ip 
        << " to: 0x" <<std::hex << target 
        << " " << nameFunc << " args (" 
        << " 0x" << std::hex << arg0
        << ", 0x" << std::hex << arg1
        << ", 0x" << std::hex << arg2 
        << ")" << std::endl;

    lstream << right;
    if (KnobEnableHexDump.Value()){
        lstream << std::setw(70) << "arg0 dump" << endl;
        DumpMemory(arg0);
        lstream << std::setw(70) << "arg1 dump" << endl;
        DumpMemory(arg1);
        lstream << std::setw(70) << "arg2 dump" << endl;
        DumpMemory(arg2);
    }
    PIN_ReleaseLock(&lock);
}

void LogIndirectCallAndArgs(THREADID tid, ADDRINT ip, ADDRINT target, BOOL taken, ADDRINT arg0, ADDRINT arg1, ADDRINT arg2)
{
    if (!taken)
        return;
    LogCallAndArgs(tid, ip, target, arg0, arg1, arg2);
}

/* ================================================================================= */
/* Log some information related to thread execution                                  */
/* ================================================================================= */
void OnThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PIN_GetLock(&lock, threadIndex + 1);
    lstream << "    * new thread started with id#" << std::hex << threadIndex  << endl;
    PIN_ReleaseLock(&lock);
}


void OnThreadFinish(THREADID threadIndex, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    PIN_GetLock(&lock, threadIndex + 1);
    lstream << "    * thread with id#" << std::hex << threadIndex << " ended" << endl;
    PIN_ReleaseLock(&lock);
}

VOID OnCallInstruction(TRACE trace, INS ins)
{
    if (INS_IsCall(ins)) {
        if (INS_IsDirectControlFlow(ins)) {
            const ADDRINT target = INS_DirectControlFlowTargetAddress(ins);

            INS_InsertPredicatedCall(ins, IPOINT_BEFORE,
                                     AFUNPTR(LogCallAndArgs),
                                     IARG_THREAD_ID,
                                     IARG_ADDRINT, INS_Address(ins),
                                     IARG_ADDRINT,
                                     target, 
                                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0, 
                                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, 
                                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2, 
                                     IARG_END);
        } else {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(LogIndirectCallAndArgs), IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR,
                           IARG_BRANCH_TAKEN, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE,
                           1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
        }
    } else {
        /* Other forms of execution transfer */
        RTN rtn = TRACE_Rtn(trace);
        // Trace jmp into DLLs (.idata section that is, imports)
        if (RTN_Valid(rtn) && SEC_Name(RTN_Sec(rtn)) == ".idata") {
            INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(LogIndirectCallAndArgs), IARG_THREAD_ID, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR,
                           IARG_BRANCH_TAKEN, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE,
                           1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
        }
    }
}

void OnTrace(TRACE trace, void *v)
{
    if (IsAddressInTraceRange(TRACE_Address(trace))) {
        /* Iterate through basic blocks */
        for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
            INS head = BBL_InsHead(bbl);

            if (KnobTraceBasicBlocks.Value())
                INS_InsertCall(head, IPOINT_BEFORE, (AFUNPTR)OnBasicBlock, IARG_THREAD_ID, IARG_ADDRINT, BBL_Address(bbl),
                               IARG_UINT32, BBL_Size(bbl), IARG_CONTEXT, IARG_END);

            if (KnobTraceInstructions.Value()) {
                //instrument every instruction in this trace
                for (INS ins = head; INS_Valid(ins); ins = INS_Next(ins))
                    OnInstruction(ins, 0);
            }

            /* Instrument function calls? */
            if (KnobTraceFunctionCalls.Value())
                OnCallInstruction(trace, BBL_InsTail(bbl));
        }
    }
}

void OnSyscallEnter(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
	ADDRINT syscall_no = PIN_GetSyscallNumber(ctxt, std);
    lstream << "    > syscall 0x" << std::hex << syscall_no << endl;

    for (int i = 0; i < 3; i++) {
        ADDRINT arg = PIN_GetSyscallArgument(ctxt, std, i);
        lstream << right << setw(15) << "arg" << i << ": 0x" << std::hex << arg << std::endl;
        
        if (KnobEnableHexDump.Value())
            DumpMemory(arg); 
    }
}
void OnSyscallExit(THREADID threadIndex, CONTEXT *ctxt, SYSCALL_STANDARD std, void *v)
{
    ADDRINT retval = PIN_GetSyscallReturn(ctxt, std);
    lstream << "        > syscall returned 0x" << std::hex << retval << endl;
}

VOID OnFini(INT32 code, VOID *v)
{
    lstream.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
int  main(int argc, char *argv[])
{
    if (PIN_Init(argc, argv))
        return Usage();

    PIN_InitSymbols();

    if (!KnobOutputFile.Value().empty()) {
		lstream.open(KnobOutputFile.Value().c_str());
    }

    //Register instrumentation Callbacks!
    IMG_AddInstrumentFunction(OnImageLoad, 0);
    IMG_AddUnloadFunction(OnImageUnload, 0);

    if (KnobTraceThreads.Value()) {
        PIN_AddThreadStartFunction(OnThreadStart, 0);
        PIN_AddThreadFiniFunction(OnThreadFinish, 0);
    }

    if(KnobEnableSyscallsTrace.Value()) {
        PIN_AddSyscallEntryFunction(OnSyscallEnter, NULL);
        PIN_AddSyscallExitFunction(OnSyscallExit, NULL);
    }

    TRACE_AddInstrumentFunction(OnTrace, 0);
    PIN_AddFiniFunction(OnFini, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
