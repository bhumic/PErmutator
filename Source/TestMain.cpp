/*
 * Tool for fine grained PE code permutation
 * Copyright (C) 2015 Bruno Humic
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "PEFunctions.h"
#include "Disassembler.h"
#include "Permutator.h"

int main(int argc, char* argv[])
{

	if (argc != 2)
	{
		std::cerr << "Usage: PErmutator <path_to_executable>" << std::endl;
		return 1;
	}

	std::fstream hInputFile;
	OpenFile(argv[1], hInputFile);
	if (!hInputFile.is_open())
	{
		std::cerr << "Invalid input file" << std::endl;
		return 1;
	}
	if (!ValidateFile(hInputFile))
	{
		std::cerr << "Invalid PE file" << std::endl;
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
			std::cerr << "Unable to create grah in memory." << std::endl;
			std::cerr << "Exiting program..." << std::endl;
			return 1;
		}
		std::cout << "Graph created in memory!" << std::endl << std::endl;

		std::cout << "Generating graphviz file..." << std::endl;
		if (permutator.VisualizeGraph(permutator.GetGraph()->GetRoot()))
			std::cout << "Graphviz file created!" << std::endl << std::endl;
		else
			std::cerr << "Error occured while creating graphviz file!" << std::endl;

		std::cout << "Writing graph to modified file on disk..." << std::endl;
		if (permutator.WriteModifiedFile())
			std::cout << "File successfully written!" << std::endl;
		else
			std::cerr << "Error occured while writing the modified file" << std::endl;
	}
	catch (std::runtime_error& error)
	{
		std::cerr << error.what() << std::endl;
	}

	hInputFile.close();

	return 0;
}
