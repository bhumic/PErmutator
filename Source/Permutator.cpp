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

#include "Permutator.h"

Permutator::Permutator(char* fileName)
{
// Init exceptions for file IO
	hInputFile.exceptions(std::fstream::badbit | std::fstream::failbit);
	gvFile.exceptions(std::fstream::badbit | std::fstream::failbit);
	outputFile.exceptions(std::fstream::badbit | std::fstream::failbit);

	InitPermutator(fileName);
}


Permutator::~Permutator()
{
}

int Permutator::CreateGraph(int creationMode)
{
	BYTE* sectionData = nullptr;

//	if (pNtHeader->FileHeader.Machine != 0x014C)
//	{
//		std::cerr << "Only 32 bit PE files supported." << std::endl;
//		return -1;
//	}

	pExecSectionHeader = FindSection(hInputFile, pNtHeader->OptionalHeader.AddressOfEntryPoint, dwFstSctHdrOffset,
		pNtHeader->FileHeader.NumberOfSections);
	if (pExecSectionHeader == nullptr)
	{
		std::cerr << "CreateGraph: Unable to read section header for executable code" << std::endl;
		exit(-1);
	}
	
	sectionData = LoadSection(hInputFile, pExecSectionHeader);
	if (sectionData == nullptr)
	{
		std::cerr << "CreateGraph: Unable to load executable section to memory" << std::endl;
		exit(-1);
	}

	DWORD dwSectionSize = pExecSectionHeader->SizeOfRawData;

	// Calculate entry point offset
	DWORD dwEpOffset = pNtHeader->OptionalHeader.AddressOfEntryPoint - 
		pExecSectionHeader->VirtualAddress;

	// Initialize array to differentiate data nodes from code nodes
	dataSize = pExecSectionHeader->SizeOfRawData;
	dataBytes = (BYTE*)malloc(dataSize);
	if (dataBytes == nullptr)
	{
		std::cerr << "CreateGraph: Unable to allocate memory for data bytes: " << dataSize << std::endl;
		exit(-1);
	}
	std::memset((BYTE*)dataBytes, 0, dataSize);

	// Create Graph
	std::vector<Block> targets;
	switch (creationMode)
	{
	case 0:
		_CreateGraph(sectionData + dwEpOffset, dwEpOffset, dwSectionSize, 0, targets);
		break;
	case 1:
		__CreateGraph(sectionData, dwEpOffset, dwSectionSize, 0);
		break;
	default:
		std::cerr << "Invalid argument for graph creation: Exiting" << std::endl;
		return 1;
	}
	CreateDataNodes(sectionData);

	return 0;
}

void Permutator::InitPermutator(char* fileName)
{
// Open file for IO operations
	try
	{
		hInputFile.open(fileName, std::ios::in | std::ios::binary);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "InitPermutator: Error while opening input file: " << e.what() << std::endl;
		exit(-1);
	}

	if (!ValidateFile(hInputFile))
	{
		std::cerr << "InitPermutator: Not a valid PE file (MZ signature)" << std::endl;
		exit(-1);
	}

	// Read the DOS header
	pDosHeader = (PIMAGE_DOS_HEADER)ReadHeader(hInputFile, sizeof(IMAGE_DOS_HEADER), 0);
	if (pDosHeader == nullptr)
	{
		std::cerr << "InitPermutator: Invalid DOS header" << std::endl;
		exit(-1);
	}

	// Read the PE Header
	pNtHeader = (PIMAGE_NT_HEADERS)ReadHeader(hInputFile, sizeof(IMAGE_NT_HEADERS), pDosHeader->e_lfanew);
	if (pNtHeader == nullptr)
	{
		std::cerr << "InitPermutator: Invalid NT header" << std::endl;
		exit(-1);
	}

	// Find the file offset to the first section header
	dwFstSctHdrOffset = pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pNtHeader->FileHeader.SizeOfOptionalHeader;			
}

bool Permutator::IsJump(std::string mnemonic)
{
	std::vector<std::string> all_jmps{ "JO", "JNO", "JS", "JNS", "JE", "JZ", "JNE", "JNZ", 
									   "JB", "JNAE", "JC", "JNB", "JAE", "JNC", "JBE", "JNA",
									   "JA", "JNBE", "JL", "JNGE", "JGE", "JNL", "JLE", "JNG",
										"JG", "JNLE", "JP", "JPE", "JNP", "JPO", "JCXZ", "JECXZ", "JMP"};
	return std::find(std::begin(all_jmps), std::end(all_jmps), mnemonic) != all_jmps.end();
}

bool Permutator::IsRegister(std::string operand)
{
	std::vector<std::string> registers{"EAX", "EBX", "ECX", "EDX", "ESP", "EBP", "ESI", "EDI", "EIP"};

	return std::find(std::begin(registers), std::end(registers), operand) != registers.end();
}

bool Permutator::IsFunctionOperandValid(std::string operand)
{
	if (operand.find("DWORD") != std::string::npos)
		return false;

	return true;
}

void Permutator::_CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset,
	std::vector<Block>& targets)
{
	_DecodeResult res;
	unsigned int decodedInstructionsCount = 0;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = blockOffset;
	_OffsetType offsetEnd;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int i;
	QWORD tmpOffset = blockOffset;
	std::string mnemonic, operand;
	bool skipFlag;

	while (1)
	{
		res = distorm_decode(offset, (const unsigned char*)sectionData, dwSectionSize,
			dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR)
		{
			free(sectionData);
			return;
		}

		for (i = 0; i < decodedInstructionsCount; ++i)
		{ 
			mnemonic = (reinterpret_cast<char*>(decodedInstructions[i].mnemonic.p));
			if (IsJump(mnemonic) ||
				mnemonic.compare("RET") == 0 ||
				mnemonic.compare("RETN") == 0 ||
				mnemonic.substr(0, 2).compare("DB") == 0)
			{
				break;
			}

			if (mnemonic.compare("CALL") == 0)
			{
				std::string functionOperand = reinterpret_cast<char*> (decodedInstructions[i].operands.p);
				if (IsRegister(functionOperand) || !IsFunctionOperandValid(functionOperand))
					continue;

				QWORD functionOffset = std::stoll(functionOperand, nullptr, 0);
				graph.AddFunctionOffset(tmpOffset, functionOffset - tmpOffset);
			}

			tmpOffset += decodedInstructions[i].size;
		}

		// Main part of graph creation
		offsetEnd = decodedInstructions[i].offset;
		DWORD blockSize = (DWORD)(offsetEnd + decodedInstructions[i].size - offset);
		Node* node = new Node();

		// Set 1 to block places in dataBytes
		for (DWORD j = 0; j < blockSize; ++j)
		{
			dataBytes[blockOffset + j] = 1;
		}

		node->SetOffset((DWORD)offset);
		node->SetInstructions(sectionData, blockSize);

// Newly added code
		skipFlag = false;
		for (std::vector<Block>::iterator it = targets.begin(); it != targets.end(); ++it)
		{
			if (((*it).offset == node->GetOffset()) && (*it).parentOffset == parentOffset)
			{
				skipFlag = true;
				break;
			}
		}
		if (skipFlag)
			return;
		Block b;
		b.offset = node->GetOffset();
		b.parentOffset = parentOffset;
		targets.push_back(b);

		if (graph.AddNode(node, (DWORD)parentOffset))
		{
			return;
		}

		if (mnemonic.compare("RET") == 0 ||
			mnemonic.compare("RETN") == 0 ||
			mnemonic.substr(0, 2).compare("DB") == 0)
			return;

		operand = reinterpret_cast<char*>(decodedInstructions[i].operands.p);
		operand.resize(decodedInstructions[i].operands.length);
		if (IsRegister(operand))
			return;

		QWORD newOffset = std::stoll(operand, nullptr, 0);

		if (!CheckRange(newOffset))
		{
			std::cerr << "Offset out of CODE section!" << std::endl;
			return;
		}

		_CreateGraph(sectionData + blockSize + (newOffset - offsetEnd - decodedInstructions[i].size),
					 newOffset,
					 dwSectionSize - (DWORD)newOffset + (DWORD)offset,
					 node->GetOffset(),
					 targets);

		if (mnemonic.compare("JMP") == 0)
			return;

		QWORD jumpFalseOffset = offsetEnd + decodedInstructions[i].size;
		
		_CreateGraph(sectionData + jumpFalseOffset - offset,
			jumpFalseOffset,
			dwSectionSize - (DWORD)jumpFalseOffset + (DWORD)offset,
			node->GetOffset(),
			targets);

		break;
	}
}

void Permutator::__CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset)
{
	_DecodeResult res;
	unsigned int decodedInstructionsCount = 0;
	_DecodeType dt = Decode32Bits;
	_OffsetType offsetEnd;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int i;
	QWORD tmpOffset = blockOffset;
	std::string mnemonic, operand;

	std::vector<Block> targets;
	std::queue<Block> blockQueue;
	bool skipFlag;
	bool disasmStopFlag;

	Block block;
	block.offset = blockOffset;
	block.parentOffset = parentOffset;
	blockQueue.push(block);

	while (!blockQueue.empty())
	{
		skipFlag = false;
		Block currentBlock = blockQueue.front();
		blockQueue.pop();

		for (std::vector<Block>::iterator it = targets.begin(); it != targets.end(); ++it)
		{
			if (((*it).offset == currentBlock.offset) && (*it).parentOffset == currentBlock.parentOffset)
			{
				skipFlag = true;
				break;
			}
		}
		if (skipFlag)
			continue;

// Disassembly part
		while (1)
		{
			disasmStopFlag = false;
			res = distorm_decode(currentBlock.offset, (const unsigned char*)(sectionData + currentBlock.offset),
				(DWORD)(dwSectionSize - currentBlock.offset),
				dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
			if (res == DECRES_INPUTERR)
			{
				free(sectionData);
				return;
			}

			for (i = 0; i < decodedInstructionsCount; ++i)
			{
				mnemonic = (reinterpret_cast<char*>(decodedInstructions[i].mnemonic.p));
				if (IsJump(mnemonic) ||
					mnemonic.compare("RET") == 0 ||
					mnemonic.compare("RETN") == 0 ||
					mnemonic.substr(0, 2).compare("DB") == 0)
				{
					disasmStopFlag = true;
					break;
				}

				if (mnemonic.compare("CALL") == 0)
				{
					std::string functionOperand = reinterpret_cast<char*> (decodedInstructions[i].operands.p);
					if (IsRegister(functionOperand) || !IsFunctionOperandValid(functionOperand))
						continue;

					QWORD functionOffset = std::stoll(functionOperand, nullptr, 0);
					graph.AddFunctionOffset(tmpOffset, functionOffset - tmpOffset);
				}

				tmpOffset += decodedInstructions[i].size;
			}
			if (disasmStopFlag)
				break;
		}

		offsetEnd = decodedInstructions[i].offset;
		DWORD blockSize = (DWORD)(offsetEnd + decodedInstructions[i].size - currentBlock.offset);
		currentBlock.blockSize = blockSize;

		// Set 1 to block places in dataBytes
		for (DWORD j = 0; j < blockSize; ++j)
		{
			dataBytes[currentBlock.offset + j] = 1;
		}

		targets.push_back(currentBlock);

		if (mnemonic.compare("RET") == 0 ||
			mnemonic.compare("RETN") == 0 ||
			mnemonic.substr(0, 2).compare("DB") == 0)
			continue;

		operand = reinterpret_cast<char*>(decodedInstructions[i].operands.p);
		operand.resize(decodedInstructions[i].operands.length);
		if (IsRegister(operand))
			continue;

		QWORD newOffset = std::stoll(operand, nullptr, 0);

		if (!CheckRange(newOffset))
		{
			std::cerr << "Offset out of CODE section!" << std::endl;
			continue;
		}

		Block positiveJumpBlock;
		positiveJumpBlock.offset = newOffset;
		positiveJumpBlock.parentOffset = currentBlock.offset;
		blockQueue.push(positiveJumpBlock);

		if (mnemonic.compare("JMP") == 0)
			continue;

		QWORD jumpFalseOffset = offsetEnd + decodedInstructions[i].size;

		if (!CheckRange(newOffset))
		{
			std::cerr << "Offset out of CODE section!" << std::endl;
			continue;
		}

		Block negativeJumpBlock;
		negativeJumpBlock.offset = jumpFalseOffset;
		negativeJumpBlock.parentOffset = currentBlock.offset;
		blockQueue.push(negativeJumpBlock);
	}
	
// Graph creation

	for (DWORD i = 0; i < targets.size(); ++i)
	{
		Block b = targets.at(i);
		Node* n = new Node();

		n->SetOffset((DWORD) b.offset);
		n->SetInstructions((BYTE*)(sectionData + b.offset), b.blockSize);
		graph.AddNode(n, (DWORD)b.parentOffset);
	}

	return;
}

bool Permutator::CheckRange(QWORD qOffset)
{
	return (qOffset < dataSize);
}

bool Permutator::VisualizeGraph(Node* n)
{
	try
	{
		gvFile.open("graph.dot", std::ios::out);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "VisualizeGraph: Unable to open output file for graphviz: " << e.what() << std::endl;
		return false;
	}

	std::string digraphStart = "digraph g {\n"
		"graph [fontsize=12 labelloc=\"t\" label=\"\" splines=true overlap=false];\n"
		"ratio = auto;\n";
	std::string digraphEnd = "}";

	try
	{
		gvFile.write(digraphStart.c_str(), digraphStart.length());
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "VisualizeGraph: Unable to write graph prologue to graphviz output file: " << e.what() << std::endl;
		return false;
	}
	
	//Node* n = graph.GetRoot();

	ProcessNode(n, gvFile);
	CreatePath(n, gvFile);

	try
	{
		gvFile.write(digraphEnd.c_str(), digraphEnd.length());
		gvFile.flush();
		gvFile.close();
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "VisualizeGraph: Error while writing graph epilogue to graphviz output file: " << e.what() << std::endl;
		return false;
	}
	
	return true;
}

void Permutator::ProcessNode(Node* n, std::ofstream& gvFile)
{
	_DecodeResult res;
	unsigned int decodedInstructionsCount = 0;
	_DecodeType dt = Decode32Bits;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];

	std::string stateStyleStart = "[ style = \"filled\" penwidth = 1 fillcolor = \"white\" fontname = \"Courier New\" "
		"shape = \"Mrecord\" label =<<table border=\"0\" cellborder=\"0\" cellpadding=\"3\" bgcolor=\"white\">\"";
	std::string stateStyleEnd = "</table>> ];\n";

	std::string stateHeaderStart = "<tr><td bgcolor=\"black\" align=\"center\" colspan=\"2\"><font color=\"white\">";
	std::string stateHeaderEnd = "</font></td></tr>";

	std::string stateDataStart = "<tr><td align=\"left\">";
	std::string stateDataEnd = "</td></tr>";

	BYTE* instructions = n->GetInstructions();
	std::stringstream stream;
	stream << std::hex << n->GetOffset();
	std::string stateName = "\"0x" + stream.str() + "\"";

	try
	{
		gvFile.write(stateName.c_str(), stateName.length());
		gvFile.write(stateStyleStart.c_str(), stateStyleStart.length());
		gvFile.write(stateHeaderStart.c_str(), stateHeaderStart.length());
		gvFile.write(stateName.c_str(), stateName.length());
		gvFile.write(stateHeaderEnd.c_str(), stateHeaderEnd.length());
		while (1)
		{
			res = distorm_decode(n->GetOffset(), (const unsigned char*)instructions, n->GetSize(),
				dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);
			if (res == DECRES_INPUTERR) {
				std::cerr << "ProcessNode: Disassembly error" << std::endl;
				return;
			}

			for (unsigned int i = 0; i < decodedInstructionsCount; ++i)
			{
				gvFile.write(stateDataStart.c_str(), stateDataStart.length());
				gvFile.write((char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].mnemonic.length);
				if (decodedInstructions[i].operands.length != 0)
				{
					gvFile.write(" ", 1);
					gvFile.write((char*)decodedInstructions[i].operands.p, decodedInstructions[i].operands.length);
				}
				gvFile.write(stateDataEnd.c_str(), stateDataEnd.length());
			}

			if (res == DECRES_SUCCESS) break;
		}
		gvFile.write(stateStyleEnd.c_str(), stateStyleEnd.length());

		for (unsigned int i = 0; i < n->GetChildren().size(); ++i)
		{
			ProcessNode(n->GetChildren().at(i), gvFile);
		}
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "ProcessNode: Error while writing node information to graphviz file: " << e.what() << std::endl;
		return;
	}

	return;
}

void Permutator::CreatePath(Node* n, std::ofstream& gvFile)
{
	std::stringstream stream;
	std::string pathAttribute = "[ penwidth = 5];\n";
	
	stream << std::hex << n->GetOffset();
	std::string stateName = "\"0x" + stream.str() + "\"";
	stream.str(std::string());

	for (unsigned int i = 0; i < n->GetChildren().size(); ++i)
	{
		stream << std::hex << n->GetChildren().at(i)->GetOffset();
		std::string childName = "\"0x" + stream.str() + "\"";
		std::string pathValue = stateName + " -> " + childName + " " + pathAttribute;
		try
		{
			gvFile.write(pathValue.c_str(), pathValue.length());
		}
		catch (std::fstream::failure e)
		{
			std::cerr << "CreatePath: Error while writing paths to graphviz output file: " << e.what() << std::endl;
			return;
		}
		
		CreatePath(n->GetChildren().at(i), gvFile);
		stream.str(std::string());
	}

	return;
}

void Permutator::CreateDataNodes(BYTE* sectionData)
{
	DWORD dataEnd;

	for (DWORD i = 0; i < dataSize; ++i)
	{
		if (dataBytes[i] == 1)
			continue;

		Node* n = new Node();
		dataEnd = i;
		while (dataBytes[dataEnd] == 0 && dataEnd < dataSize)
		{
			dataEnd++;
		}

		n->SetOffset(i);
		n->SetInstructions(sectionData + i, dataEnd - i);
		dataNodes.push_back(n);

		i = dataEnd - 1;
	}
}

bool Permutator::WriteModifiedFile()
{
	try
	{
		outputFile.open("permutatedFile.exe", std::ios::out | std::ios::binary);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteModifiedFile: Error while opening stream to modified file: " << e.what() << std::endl;
		return false;
	}
	
	try
	{
		// Write DOS header
		outputFile.write((char*)pDosHeader, sizeof(IMAGE_DOS_HEADER));

		// Write NT header
		outputFile.seekp(pDosHeader->e_lfanew, std::ios::beg);
		outputFile.write((char*)pNtHeader, sizeof(IMAGE_NT_HEADERS));
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteModifiedFile: Error while writing DOS/NT headers to modified file: " << e.what() << std::endl;
		return false;
	}
	

	// Write section headers and section data
	BYTE* sectionData = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hInputFile, IMAGE_SIZEOF_SECTION_HEADER, dwFstSctHdrOffset + i*IMAGE_SIZEOF_SECTION_HEADER);
		if (pSectionHeader == nullptr)
		{
			std::cerr << "WriteModifiedFile: Invalid section header read" << std::endl;
			return false;
		}
		
		if (!WriteSectionHeader(pSectionHeader, i, outputFile, dwFstSctHdrOffset))
		{
			std::cerr << "WriteModifiedFile: Error writing the section header: " << pSectionHeader->Name << std::endl;
			continue;
		}

		if ((pNtHeader->OptionalHeader.AddressOfEntryPoint >= pSectionHeader->VirtualAddress) &&
			(pNtHeader->OptionalHeader.AddressOfEntryPoint < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)))
		{
			sectionData = (BYTE*)malloc(pSectionHeader->SizeOfRawData);
			WriteGraph(graph.GetRoot(), sectionData);
			WriteData(sectionData);
			if (!WriteSection(outputFile, pSectionHeader, sectionData))
			{
				std::cerr << "WriteModifiedFile: Error while writing data of executable section: " << pSectionHeader->Name << std::endl;
				continue;
			}
		}
		else
		{
			sectionData = LoadSection(hInputFile, pSectionHeader);
			if (sectionData == nullptr)
			{
				std::cerr << "WriteModifiedFile: Unable to load section: " << pSectionHeader->Name << std::endl;
				continue;
			}
			if (!WriteSection(outputFile, pSectionHeader, sectionData))
			{
				std::cerr << "WriteModifiedFile: Error while writing data of section: " << pSectionHeader->Name << std::endl;
				continue;
			}
		}
		

		free(pSectionHeader);
		free(sectionData);
		sectionData = nullptr;
		pSectionHeader = nullptr;
	}

// Write overlays if any
	PIMAGE_SECTION_HEADER pLastSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hInputFile, IMAGE_SIZEOF_SECTION_HEADER,
		dwFstSctHdrOffset + IMAGE_SIZEOF_SECTION_HEADER * (pNtHeader->FileHeader.NumberOfSections - 1));
	DWORD overlaySize;
	BYTE* overlay = ExtractOverlays(hInputFile, pLastSectionHeader, &overlaySize);
	if (overlay != nullptr && overlaySize != 0)
	{
		if (!WriteDataToFile(outputFile, pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData,
			overlaySize, overlay))
		{
			std::cerr << "WriteModifiedFile: Error while writing overlay data to modified file" << std::endl;
			return false;
		}
	}

	try
	{
		outputFile.flush();
		outputFile.close();
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "WriteModifiedFile: Error while closing modified file stream: " << e.what() << std::endl;
		return false;
	}

	return true;
}

void Permutator::WriteGraph(Node* n, BYTE* sectionData)
{
	std::memcpy((BYTE*)sectionData + n->GetOffset(), n->GetInstructions(), n->GetSize());
	for (DWORD i = 0; i < n->GetChildren().size(); ++i)
		WriteGraph(n->GetChildren().at(i), sectionData);

	return;
}

void Permutator::WriteData(BYTE* sectionData)
{
	for (DWORD i = 0; i < dataNodes.size(); ++i)
	{
		Node n = *dataNodes.at(i);
		std::memcpy((BYTE*)sectionData + n.GetOffset(), n.GetInstructions(), n.GetSize());
	}
}

Graph* Permutator::GetGraph()
{
	return &graph;
}
