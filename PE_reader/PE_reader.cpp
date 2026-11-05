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
函数名称：print_optional_header64
输入：const NT_HEADER64 NT64
说明：打印可选头64位重要成员
*/
void print_optional_header64(const NT_HEADER64 NT64)
{
	const int prtw_name = 22; // 名称最大宽度
	const int prtw_val = 16; // 值最大宽度

	OPTIONAL_HEADER64 optH64 = NT64.OptionalHeader;

	// 打印
	std::cout << "可选头（64位）：\n";
	std::cout << std::setw(prtw_name) << std::left << "参数名称"
			  << std::setw(prtw_val) << "原始值" << std::endl;
	std::cout << std::setw(prtw_name) << "Magic" << std::hex
			  << std::setw(prtw_val) << optH64.Magic << std::endl;
	std::cout << std::setw(prtw_name) << "Addr of EP" << std::hex
			  << std::setw(prtw_val) << optH64.AddrOfEP << std::endl;
	std::cout << std::setw(prtw_name) << "Image Base" << std::hex
			  << std::setw(prtw_val) << optH64.ImageBase << std::endl;
	std::cout << std::setw(prtw_name) << "Section Alignment" << std::hex
			  << std::setw(prtw_val) << optH64.SectionAlignment << std::endl;
	std::cout << std::setw(prtw_name) << "File Alignment" << std::hex
			  << std::setw(prtw_val) << optH64.FileAlignment << std::endl;
	std::cout << std::setw(prtw_name) << "Size of Image" << std::hex
			  << std::setw(prtw_val) << optH64.SizeOfImage << std::endl;
	std::cout << std::setw(prtw_name) << "Size of Header" << std::hex
			  << std::setw(prtw_val) << optH64.SizeOfHeaders << std::endl;
	std::cout << std::setw(prtw_name) << "Sub System" << std::hex
			  << std::setw(prtw_val) << optH64.Subsys << std::endl;
	std::cout << std::setw(prtw_name) << "Data Director count" << std::hex
			  << std::setw(prtw_val) << optH64.NumOfRvaAndSizes << std::endl;
	std::cout << std::endl;
	std::cout << std::dec << std::right;
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

	if (dosH.e_lfanew < static_cast<int32_t>(sizeof(DOS_HEADER))) // 非法NT头偏移
		return false;

	const size_t NT_off = static_cast<size_t>(dosH.e_lfanew);
	const size_t magic_off = NT_off + offsetof(NT_HEADER64, OptionalHeader);
	if (magic_off > buffer.size() - sizeof(uint32_t)) // 超出文件长度
		return false;

	uint32_t sign = 0;
	memcpy(&sign, buffer.data() + NT_off, sizeof(uint32_t));
	if (sign != NT_SIGNATURE) // 非NT头签名
		return false;

	uint16_t magic = 0;
	memcpy(&magic, buffer.data() + magic_off, sizeof(uint16_t));
	if (magic != 0x10b && magic != 0x20b) // 非PE32/PE32+
		return false;

	return true;
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
		std::cerr << "非PE文件" << std::endl;
		return FILE_NOT_PE;
	}

	// 打印
	std::cout << "\nDOS头：\n";
	std::cout << std::setw(prtw_name) << std::left << "参数名称";
	std::cout << std::setw(prtw_val)  << "原始值" << std::endl;
	
	std::cout << std::setw(prtw_name) << "Magic number" << std::hex
			  << std::setw(prtw_val) << dosH.e_magic << std::endl;
	std::cout << std::setw(prtw_name) << "Addr of NT header" << std::hex
			  << std::setw(prtw_val) << dosH.e_lfanew << std::endl;
	std::cout << std::dec << std::right;

	return 0;
}

/*
函数名称：parse_file_header
输入：const NT_HEADER64 NT64
输出：int (status)
说明：打印64位文件头重要成员
*/
int parse_file_header(const NT_HEADER64 NT64)
{
	const int prtw_name = 18; // 名称最大宽度
	const int prtw_val = 8; // 值最大宽度

	if (NT64.FileHeader.SizeOfOptionalHeader != sizeof(OPTIONAL_HEADER64))
	{
		std::cerr << "可选头长度异常（非PE32+）\n";
		return FILE_NOT_PE;
	}

	FILE_HEADER FileH = NT64.FileHeader;

	// 打印
	std::cout << "文件头：\n";
	std::cout << std::setw(prtw_name) << std::left << "参数名称"
		<< std::setw(prtw_val) << "原始值" << std::endl;
	std::cout << std::setw(prtw_name) << "Machine" << std::hex
		<< std::setw(prtw_val) << FileH.Machine << std::endl;
	std::cout << std::setw(prtw_name) << "SectionCount" << std::hex
		<< std::setw(prtw_val) << FileH.NumOfSections << std::endl;
	std::cout << std::setw(prtw_name) << "SizeOfOptHdr" << std::hex
		<< std::setw(prtw_val) << FileH.SizeOfOptionalHeader << std::endl;
	std::cout << std::setw(prtw_name) << "Characteristics" << std::hex
		<< std::setw(prtw_val) << FileH.Characteristics << std::endl;
	std::cout << std::endl;
	std::cout << std::dec << std::right;

	return 0;
}

/*
函数名称：parse_NT_header
输入：std::vector<uint8_t>& buffer
输出：int (status)
说明：解析并打印NT头成员
*/
int parse_NT_header(std::vector<uint8_t>& buffer)
{
	if (!is_PE_file(buffer))
	{
		std::cerr << "非PE文件\n";
		return FILE_NOT_PE;
	}

	int32_t lfanew;
	memcpy(&lfanew, buffer.data() + 0x3C, sizeof(lfanew));
	const size_t off = static_cast<size_t>(lfanew);
	if (off > buffer.size() || buffer.size() - off < sizeof(NT_HEADER64))
	{
		std::cerr << "NT头不完整\n";
		return FILE_NOT_PE;
	}
	// TODO 32位判断

	uint16_t magic = 0;
	size_t off_sign = offsetof(NT_HEADER64, OptionalHeader);
	memcpy(&magic, buffer.data() + off + off_sign, sizeof(uint16_t));
	if (magic == 0x10b)
	{
		std::cerr << "暂不支持32位文件\n";
		return FILE_NOT_SUPPORT_PE32;
	}
	else if (magic != 0x20b)
	{
		std::cerr << "可选头magic非法\n";
		return FILE_NOT_PE;
	}

	NT_HEADER64 NT64 {0};
	memcpy(&NT64, buffer.data() + off, sizeof(NT_HEADER64));

	// NT头打印
	std::cout << "\nNT头签名：PE\n\n";

	int status = parse_file_header(NT64);
	if (status)
		return status;
	
	print_optional_header64(NT64);

	return status;
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

	err_stat = parse_NT_header(buffer);
	if (err_stat)
		return err_stat;

	return 0;
}
