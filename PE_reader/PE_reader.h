// By StarP1t
#pragma once

// 宏定义
#define NAME_BUFF_SIZE 256
#define FILE_BUFF_SIZE 1024

// 错误宏定义
#define FILE_OPEN_FAIL_ERR -1
#define FILE_EMPTY_ERR -2
#define FILE_READ_FAIL_ERR -3
#define FILE_NOT_PE -4

// 头文件
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>

// 函数声明
void print_help_info();
int PE_Check();
int Parse_Header();
