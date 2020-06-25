/*
 * process tracer using intel pin tool
 *  trace process execution state by instruction dumping CPU context and memory access
 *  and few other utilty function
 *
 *  (c) krishs.patil@gmail.com  
*/

#ifndef __PROCESSTRACER_INCLUDE_H__
#define __PROCESSTRACER_INCLUDE_H__

#include "pin.H"
#include "vector"

using namespace  std;

#define MAX_REG_PARTS 6  /*rax eax ax ah al none*/

typedef std::vector<std::pair<ADDRINT, ADDRINT>> TraceFilterRange;

struct RegisterReference {
    const char*       name[MAX_REG_PARTS];
    const char*		alias;
    LEVEL_BASE::REG   ref;
};

static struct RegisterReference AllContextRegs[] = {
#if defined(__x86_64__) || defined(_M_X64)
    { { "rax", "eax", "ax", "ah", "al", 0 }, "rax", LEVEL_BASE::REG_RAX },
    { { "rbx", "ebx", "bx", "bh", "bl", 0 }, "rbx", LEVEL_BASE::REG_RBX },
    { { "rcx", "ecx", "cx", "ch", "cl", 0 }, "rcx", LEVEL_BASE::REG_RCX },
    { { "rdx", "edx", "dx", "dh", "dl", 0 }, "rdx", LEVEL_BASE::REG_RDX },
    { { "rdi", "edi", "di", 0 }, "rdi", LEVEL_BASE::REG_RDI },
    { { "rsi", "esi", "si", 0 }, "rsi", LEVEL_BASE::REG_RSI },
    { { "rsp", "esp", "sp", 0 }, "rsp", LEVEL_BASE::REG_RSP },
    { { "rbp", "ebp", "bp", 0 }, "rbp", LEVEL_BASE::REG_RBP },
    { { "rip", "eip", "ip", 0 }, "rip", LEVEL_BASE::REG_RIP },
    { { "r8", 0 }, "r8", LEVEL_BASE::REG_R8 },
    { { "r9", 0 }, "r9", LEVEL_BASE::REG_R9 },
    { { "r10", 0 }, "r10", LEVEL_BASE::REG_R10 },
    { { "r11", 0 }, "r11", LEVEL_BASE::REG_R11 },
    { { "r12", 0 }, "r12", LEVEL_BASE::REG_R12 },
    { { "r13", 0 }, "r13", LEVEL_BASE::REG_R13 },
    { { "r14", 0 }, "r14", LEVEL_BASE::REG_R14 },
    { { "r15", 0 }, "r15", LEVEL_BASE::REG_R15 },
#endif
#if defined(__i386) || defined(_M_IX86)
    { { "eax", "ax", "ah", "al", "" }, "eax", LEVEL_BASE::REG_EAX },
    { { "ebx", "bx", "bh", "bl", "" }, "ebx", LEVEL_BASE::REG_EBX },
    { { "ecx", "cx", "ch", "cl", "" }, "ecx", LEVEL_BASE::REG_ECX },
    { { "edx", "dx", "dh", "dl", "" }, "edx", LEVEL_BASE::REG_EDX },
    { { "edi", "di", "" }, "edi", LEVEL_BASE::REG_EDI },
    { { "esi", "si", "" }, "esi", LEVEL_BASE::REG_ESI },
    { { "eip", "ip", "" }, "eip", LEVEL_BASE::REG_EIP },
    { { "esp", "sp", "" }, "esp", LEVEL_BASE::REG_ESP },
    { { "ebp", "bp", "" }, "ebp", LEVEL_BASE::REG_EBP },
#endif
    { { "fs", 0 }, "fs", REG_SEG_FS },
    { { "gs", 0 }, "gs", REG_SEG_GS },
    { { 0 }, 0, REG_INVALID() }
};

#endif //__PROCESSTRACE_INCLUDE_H__