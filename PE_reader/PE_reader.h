// By StarP1t
#pragma once

// 宏定义
#define NAME_BUFF_SIZE 256
#define FILE_BUFF_SIZE 1024

// 错误宏定义
#define FILE_OPEN_FAIL_ERR -1
#define FILE_EMPTY_ERR -2
#define FILE_READ_FAIL_ERR -3

// 头文件
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>

// 函数声明
void print_startup_info();

int file_open(std::ifstream& file);
int file_load(std::ifstream& file, std::vector<uint8_t>& buffer);

bool is_PE_file(std::vector<uint8_t>& buffer);