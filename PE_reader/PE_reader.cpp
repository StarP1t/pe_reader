// By StarP1t
// 头文件
#include <cstring>
#include <fstream>
#include <iomanip>
#include <vector>
#include "PE_reader.h"

//
// 实现函数
//

/*
函数名称：print_help_info
说明：打印帮助信息
*/
void print_help_info()
{
	std::cout << std::endl;
	std::cout << "用法：无参数，[-h] 或 [-c]" << "\n\n";

	std::cout << "选项：" << std::endl;
	std::cout << "-h : 打印帮助信息" << std::endl;
	std::cout << "-c : 检查是否是pe文件" << std::endl;
}

/*
函数名称：print_startup_info
说明：打印文件名形式信息提示
*/
void print_filename_help()
{
	std::cout << "文件名形式:" << std::endl;
	std::cout << std::setw(4) << ' ' << std::left << std::setw(26) << "a.txt";
	std::cout << ": 不带路径形式" << std::endl;
	std::cout << std::setw(4) << ' ' << std::setw(26) << "..\\data\\b.dat";
	std::cout << ": 相对路径形式" << std::endl;
	std::cout << std::setw(4) << ' ' << std::setw(26) << "C:\\Windows\\System32\\c.dat";
	std::cout << ": 绝对路径形式" << std::endl;
}

/*
函数名称：file_open
输入：ifstream& file
输出：int (status)
说明：获取文件路径，二进制只读打开文件
*/
int file_open(std::ifstream& file)
{
	std::string path;
	std::cout << "请输入文件名(两侧无引号): ";
	std::getline(std::cin, path);
	if (path.empty())
		return FILE_OPEN_FAIL_ERR;
	std::cout << std::endl;

	file.open(path, std::ios::binary);
	if (!file)
	{
		std::cerr << "文件\"" << path << "\"打开失败!" << std::endl;
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
函数名称：get_file
输入：std::vector<uint8_t>& buffer
输出：int status
说明：获取文件并加载到缓冲区
*/
int get_file(std::vector<uint8_t>& buffer)
{
	std::ifstream file;
	if (file_open(file))
		return FILE_OPEN_FAIL_ERR;

	int status = file_load(file, buffer);
	if (status)
		return status;
	file.close();

	return 0;
}

/*
函数名称：parse_DOS_header
输入：std::vector<uint8_t>& buffer
输出：int (status)
说明：解析并打印dos头重要成员
*/
int parse_DOS_header(std::vector<uint8_t>& buffer)
{
	const int prtw_name = 20; // 名称最大宽度
	const int prtw_val = 8; // 值最大宽度

	DOS_HEADER dosH;

	if (buffer.size() < sizeof(DOS_HEADER))
	{
		std::cerr << "文件太小，非PE文件\n";
		return FILE_NOT_PE;
	}
	std::memcpy(&dosH, buffer.data(), sizeof(DOS_HEADER));

	if (dosH.e_magic != DOS_SIGNATURE)
	{
		std::cout << "非PE文件" << std::endl;
		return FILE_NOT_PE;
	}

	// 打印
	std::cout << std::endl;
	std::cout << std::setw(prtw_name) << std::left << "参数名称";
	std::cout << std::setw(prtw_val)  << "原始值" << std::endl;
	
	std::cout << std::setw(prtw_name) << "Magic number" << std::hex
			  << std::setw(prtw_val) << dosH.e_magic << std::endl;
	std::cout << std::setw(prtw_name) << "Addr of NT header" << std::hex
			  << std::setw(prtw_val) << dosH.e_lfanew << std::endl;
	std::cout << std::endl;

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
	DOS_HEADER dosH;

	if (buffer.size() < sizeof(DOS_HEADER)) // 文件太小
		return false;

	std::memcpy(&dosH, buffer.data(), sizeof(DOS_HEADER));
	
	if (dosH.e_magic != DOS_SIGNATURE) // 非MZ头
		return false;

	if (dosH.e_lfanew < 0) // 非法NT头偏移
		return false;

	size_t offset = static_cast<size_t>(dosH.e_lfanew);
	if (offset > buffer.size() - sizeof(uint32_t)) // 超出文件长度
		return false;
	
	uint32_t sign = 0;
	memcpy(&sign, buffer.data() + offset, sizeof(uint32_t));

	return sign == NT_SIGNATURE;
}

//
// 综合调用函数
//

/*
函数名称：PE_check
输出：int (status)
说明：检查输入文件是否是PE文件
*/
int PE_Check()
{
	std::vector<uint8_t> buffer;
	int err_stat;

	print_filename_help();

	err_stat = get_file(buffer);
	if (err_stat)
		return err_stat;

	std::cout << "文件类型：";
	if (!is_PE_file(buffer))
	{
		std::cout << "非PE文件" << std::endl;
		return FILE_NOT_PE;
	}
	std::cout << "PE文件" << std::endl;

	return 0;
}

/*
函数名称：parse_header
输出：int (status)
说明：TODO 解析PE头
*/
int Parse_Header()
{
	std::vector<uint8_t> buffer;
	int err_stat = 0;

	print_filename_help();

	err_stat = get_file(buffer);
	if (err_stat)
		return err_stat;

	err_stat = parse_DOS_header(buffer);
	if (err_stat)
		return err_stat;

	return 0;
}
