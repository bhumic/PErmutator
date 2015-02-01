#include "PEFunctions.h"
#include "Disassembler.h"
#include "Permutator.h"

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
		int creationMode;

		std::cout << "Enter graph creation mode:" << std::endl;
		std::cout << "0 - Recursive creation algorithm" << std::endl;
		std::cout << "1 - Non-Recursive creation algorithm" << std::endl;
		std::cin >> creationMode;
		if (permutator.CreateGraph(creationMode) != 0)
		{
			std::cout << "Unable to create grah in memory." << std::endl;
			std::cout << "Exiting program..." << std::endl;
			return 1;
		}
		std::cout << "Graph created in memory!" << std::endl << std::endl;

		std::cout << "Generating graphviz file..." << std::endl;
		if (permutator.VisualizeGraph(permutator.GetGraph()->GetRoot()))
			std::cout << "Graphviz file created!" << std::endl << std::endl;
		else
			std::cout << "Error occured while creating graphviz file!" << std::endl;

		std::cout << "Writing graph to modified file on disk..." << std::endl;
		if (permutator.WriteModifiedFile())
			std::cout << "File successfully written!" << std::endl;
		else
			std::cout << "Error occured while writing the modified file" << std::endl;
	}
	catch (std::runtime_error& error)
	{
		std::cout << error.what() << std::endl;
	}

	hInputFile.close();

	return 0;
}
