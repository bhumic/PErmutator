#ifdef _WIN32
	#include "PEFunctions.h"
	#include "Disassembler.h"
	#include "Permutator.h"
#elif __linux__
	#include "../Headers/PEFunctions.h"
	#include "../Headers/Disassembler.h"
	#include "../Headers/Permutator.h"
#endif

int main(int argc, char* argv[])
{

	if (argc != 2)
	{
		std::cout << "Usage: PErmutator <path_to_executable>" << std::endl;
		return 1;
	}

	std::fstream hInputFile;
	OpenFile(argv[1], hInputFile);
	if (!hInputFile.is_open())
	{
		std::cout << "Invalid input file" << std::endl;
		return 1;
	}
	if (!ValidateFile(hInputFile))
	{
		std::cout << "Invalid PE file" << std::endl;
		return 1;
	}

	try
	{
		Permutator permutator(hInputFile);
		permutator.CreateGraph();
		permutator.VisualizeGraph(permutator.GetGraph()->GetRoot());
		permutator.WriteModifiedFile();
	}
	catch (std::runtime_error& error)
	{
		std::cout << error.what() << std::endl;
	}

	hInputFile.close();

	return 0;
}