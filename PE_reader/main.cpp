// By StarP1t
#include "PE_reader.h"

int main()
{
	print_startup_info();

	std::ifstream file;
	if (file_open(file))
		return FILE_OPEN_FAIL_ERR;

	std::vector<uint8_t> buffer;
	int status = file_load(file, buffer);
	if (status)
		return status;
	file.close();

	std::cout << "文件类型：";
	if (is_PE_file(buffer))
		std::cout << "PE文件" << std::endl;
	else
		std::cout << "非PE文件" << std::endl;

	return 0;
}
