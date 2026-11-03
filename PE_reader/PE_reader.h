// By StarP1t
#pragma once

// 宏定义
#define DOS_SIGNATURE 0x5A4D // MZ
#define NT_SIGNATURE 0x00004550 // PE00

// 错误宏定义
#define FILE_OPEN_FAIL_ERR 1
#define FILE_EMPTY_ERR 2
#define FILE_READ_FAIL_ERR 3
#define FILE_NOT_PE 4

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

// 函数声明
void print_help_info();
int PE_Check();
int Parse_Header();
