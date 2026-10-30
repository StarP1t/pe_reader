// By StarP1t
// 头文件
#include <Windows.h>
#include <cstring>
#include "PE_reader.h"

/*
函数名称：print_startup_info
说明：打印文件名形式信息提示
*/
void print_startup_info()
{
	std::cout << "文件名形式:" << std::endl;
	std::cout << std::setw(4) << ' ' << std::left << std::setw(26) << "a.txt";
	std::cout << ": 不带路径形式" << std::endl;
	std::cout << std::setw(4) << ' ' << std::setw(26) << "..\\data\\b.dat";
	std::cout << ": 相对路径形式" << std::endl;
	std::cout << std::setw(4) << ' ' << std::setw(26) << "C:\\Windows\\System32\\c.dat";
	std::cout << ": 绝对相对路径形式" << std::endl;
}

/*
函数名称：file_open
输入：ifstream& file
输出：int (status)
说明：获取文件路径，二进制只读打开文件
*/
int file_open(std::ifstream& file)
{
	char pwd[NAME_BUFF_SIZE] {0};
	std::cout << "请输入文件名(无空白字符/引号): ";
	std::cin >> pwd;
	if (!std::cin)
		return FILE_OPEN_FAIL_ERR;
	std::cout << std::endl;

	file.open(pwd, std::ios::binary);
	if (!file)
	{
		std::cerr << "文件\"" << pwd << "\"打开失败!" << std::endl;
		file.clear();
		return FILE_OPEN_FAIL_ERR;
	}

	return 0;
}

/*
函数名称：file_load
输入：ifstream& file, vector<uint8_t>& buffer
输出：int (status)
说明：将文件读入到缓冲区
*/
int file_load(std::ifstream& file, std::vector<uint8_t>& buffer)
{
	if (!file.is_open())
	{
		std::cerr << "文件没有被正确打开!" << std::endl;
		return FILE_OPEN_FAIL_ERR;
	}

	// 获取文件大小
	file.seekg(0, std::ios::end);
	std::streampos fsize = file.tellg();
	file.seekg(0, std::ios::beg);

	if (fsize <= 0)
	{
		std::cerr << "文件为空!" << std::endl;
		return FILE_EMPTY_ERR;
	}

	// 读入文件
	buffer.resize(static_cast<size_t>(fsize));
	file.read(reinterpret_cast<char*>(buffer.data()), fsize);

	if (!file)
	{
		std::cerr << "文件读取失败!" << std::endl;
		return FILE_READ_FAIL_ERR;
	}

	std::cout << "文件加载成功!" << std::endl;
	return 0;
}

/*
函数名称：is_PE_file
输入：std::vector<uint8_t>& buffer
输出：bool
说明：判断缓冲区是否是PE文件
*/
bool is_PE_file(std::vector<uint8_t>& buffer)
{
	IMAGE_DOS_HEADER dosH;
	std::memcpy(&dosH, buffer.data(), sizeof(IMAGE_DOS_HEADER));

	return dosH.e_magic == 0x5A4D;
}
