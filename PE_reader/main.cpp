// By StarP1t
#include "PE_reader.h"

int main(int argc, char* argv[])
{
	int err_stat = 0;

	// TODO 完整参数检查
	if (argc < 2) // 无参默认解析头
		err_stat = Parse_Header();
	else if (argc < 3) // 一参
	{
		std::string arg = argv[1];

		if (arg == "-c") // check
			err_stat = PE_Check();
		else if (arg == "-h") // help
			print_help_info();
	}

	return err_stat;
}
