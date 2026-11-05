// By StarP1t
#pragma once

// 宏定义
#define DOS_SIGNATURE 0x5A4D // MZ
#define NT_SIGNATURE 0x00004550 // PE00
#define NUMOF_DIR_ENTRIES 16

// 错误宏定义
#define FILE_OPEN_FAIL_ERR 1
#define FILE_EMPTY_ERR 2
#define FILE_READ_FAIL_ERR 3
#define FILE_NOT_PE 4
#define FILE_NOT_SUPPORT_PE32 5

// 头文件
#include <cstdint>
#include <iostream>
#include <string>

// 结构体定义
// PE头定义摘录自 winnt.h
struct DOS_HEADER
{
	uint16_t e_magic;
	uint16_t e_cblp, e_cp;
	uint16_t e_crlc, e_cparhdr;
	uint16_t e_minalloc, e_maxalloc;
	uint16_t e_ss, e_sp;
	uint16_t e_csum;
	uint16_t e_ip, e_cs;
	uint16_t e_lfarlc;
	uint16_t e_ovno;
	uint16_t e_res[4];
	uint16_t e_oemid, e_oeminfo;
	uint16_t e_res2[10];
	int32_t e_lfanew;
};

struct DATA_DIRECTORY
{
	uint32_t VA;
	uint32_t Size;
};

struct FILE_HEADER 
{
	uint16_t Machine;
	uint16_t NumOfSections;
	uint32_t TimeDateStamp;
	uint32_t PtrToSymbolTable;
	uint32_t NumOfSymbols;
	uint16_t SizeOfOptionalHeader;
	uint16_t Characteristics;
};

struct OPTIONAL_HEADER64
{
	uint16_t Magic;
	uint8_t MajorLinkerVersion;
	uint8_t MinorLinkerVersion;
	uint32_t SizeOfCode;
	uint32_t SizeOfInitializedData;
	uint32_t SizeOfUninitializedData;
	uint32_t AddrOfEP;
	uint32_t BaseOfCode;
	uint64_t ImageBase;
	uint32_t SectionAlignment;
	uint32_t FileAlignment;
	uint16_t MajorOperatingSystemVersion;
	uint16_t MinorOperatingSystemVersion;
	uint16_t MajorImageVersion;
	uint16_t MinorImageVersion;
	uint16_t MajorSubsystemVersion;
	uint16_t MinorSubsystemVersion;
	uint32_t Win32VersionValue;
	uint32_t SizeOfImage;
	uint32_t SizeOfHeaders;
	uint32_t CheckSum;
	uint16_t Subsys;
	uint16_t DllCharacteristics;
	uint64_t SizeOfStackReserve;
	uint64_t SizeOfStackCommit;
	uint64_t SizeOfHeapReserve;
	uint64_t SizeOfHeapCommit;
	uint32_t LoaderFlags;
	uint32_t NumOfRvaAndSizes;
	DATA_DIRECTORY DataDir[NUMOF_DIR_ENTRIES];
};

struct NT_HEADER64
{
	uint32_t Signature;
	FILE_HEADER FileHeader;
	OPTIONAL_HEADER64 OptionalHeader;
};

// 函数声明
void print_help_info();
int PE_Check();
int Parse_Header();
