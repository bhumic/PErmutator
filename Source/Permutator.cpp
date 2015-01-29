#ifdef _WIN32
	#include "Permutator.h"
#elif __linux__
	#include "../Headers/Permutator.h"
#endif

Permutator::Permutator(std::fstream& hInputFile)
{
	this->hInputFile = &hInputFile;
	InitPermutator();
}


Permutator::~Permutator()
{
}

int Permutator::CreateGraph(int creationMode)
{
	BYTE* sectionData = nullptr;
	PIMAGE_SECTION_HEADER *pSectionHeader = nullptr;

	PIMAGE_SECTION_HEADER ppSectionHeader;
	pSectionHeader = &ppSectionHeader;

	if (pNtHeader->FileHeader.Machine != 0x014C)
	{
		std::cout << "Only 32 bit PE files supported." << std::endl;
		return -1;
	}

	sectionData = LoadExecutableSection(*hInputFile, pDosHeader, pNtHeader, dwFstSctHdrOffset, pSectionHeader);

	if (sectionData == nullptr)
		return -1;

	DWORD dwSectionSize = (*pSectionHeader)->SizeOfRawData;

	// Calculate entry point offset
	DWORD dwEpOffset = pNtHeader->OptionalHeader.AddressOfEntryPoint - 
		(*pSectionHeader)->VirtualAddress;

	// Initialize array to differentiate data nodes from code nodes
	dataSize = (*pSectionHeader)->SizeOfRawData;
	dataBytes = (BYTE*)malloc(dataSize);
	std::memset((BYTE*)dataBytes, 0, dataSize);

	// Create Graph
	switch (creationMode)
	{
	case 0:
		_CreateGraph(sectionData + dwEpOffset, dwEpOffset, dwSectionSize, 0);
		break;
	case 1:
		__CreateGraph(sectionData, dwEpOffset, dwSectionSize, 0);
		break;
	default:
		std::cout << "Invalid argument for graph creation: Enter 0 for Recursive Creation or 1 for Queue Createion" << std::endl;
		return 1;
	}
	CreateDataNodes(sectionData);

	return 0;
}

void Permutator::InitPermutator()
{
	// Read the DOS header
	pDosHeader = (PIMAGE_DOS_HEADER)ReadHeader(*hInputFile, sizeof(IMAGE_DOS_HEADER), 0);
	if (pDosHeader == nullptr)
		throw std::runtime_error("Invalid DOS header");

	// Read the PE Header
	pNtHeader = (PIMAGE_NT_HEADERS)ReadHeader(*hInputFile, sizeof(IMAGE_NT_HEADERS), pDosHeader->e_lfanew);
	if (pNtHeader == nullptr)
		throw std::runtime_error("Invalid PE header");

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

void Permutator::_CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset)
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
			std::cout << "Offset out of CODE section!" << std::endl;
			return;
		}

		_CreateGraph(sectionData + blockSize + (newOffset - offsetEnd - decodedInstructions[i].size),
					 newOffset,
					 dwSectionSize - (DWORD)newOffset + (DWORD)offset,
					 node->GetOffset());

		if (mnemonic.compare("JMP") == 0)
			return;

		QWORD jumpFalseOffset = offsetEnd + decodedInstructions[i].size;
		
		_CreateGraph(sectionData + jumpFalseOffset - offset,
			jumpFalseOffset,
			dwSectionSize - (DWORD)jumpFalseOffset + (DWORD)offset,
			node->GetOffset());

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
			std::cout << "Offset out of CODE section!" << std::endl;
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
			std::cout << "Offset out of CODE section!" << std::endl;
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
	std::ofstream gvFile ("graph.gh");

	std::string digraphStart = "digraph g {\n"
		"graph [fontsize=12 labelloc=\"t\" label=\"\" splines=true overlap=false];\n"
		"ratio = auto;\n";
	std::string digraphEnd = "}";
	gvFile.write(digraphStart.c_str(), digraphStart.length());
	
	//Node* n = graph.GetRoot();

	ProcessNode(n, gvFile);
	CreatePath(n, gvFile);

	gvFile.write(digraphEnd.c_str(), digraphEnd.length());
	gvFile.close();
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
			std::cout << "VisualizeGraph(): Disassembly error" << std::endl;
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
		gvFile.write(pathValue.c_str(), pathValue.length());
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
	outputFile.open("permutatedFile.exe", std::ios::out | std::ios::binary);
	
	// Write DOS header
	outputFile.write((char*)pDosHeader, sizeof(IMAGE_DOS_HEADER));

	// Write NT header
	outputFile.seekp(pDosHeader->e_lfanew, std::ios::beg);
	outputFile.write((char*)pNtHeader, sizeof(IMAGE_NT_HEADERS));

	// Write section headers and section data
	BYTE* sectionData = nullptr;
	PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(*hInputFile, IMAGE_SIZEOF_SECTION_HEADER, dwFstSctHdrOffset + i*IMAGE_SIZEOF_SECTION_HEADER);
		if (pSectionHeader == nullptr)
		{
			return nullptr;
		}
		
		WriteSectionHeader(pSectionHeader, i, outputFile, dwFstSctHdrOffset);

		if ((pNtHeader->OptionalHeader.AddressOfEntryPoint >= pSectionHeader->VirtualAddress) &&
			(pNtHeader->OptionalHeader.AddressOfEntryPoint < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)))
		{
			sectionData = (BYTE*)malloc(pSectionHeader->SizeOfRawData);
			WriteGraph(graph.GetRoot(), sectionData);
			WriteData(sectionData);
			WriteSection(outputFile, pSectionHeader, sectionData);
		}
		else
		{
			sectionData = LoadSection(*hInputFile, pSectionHeader);
			WriteSection(outputFile, pSectionHeader, sectionData);
		}
		

		free(pSectionHeader);
		free(sectionData);
		sectionData = nullptr;
		pSectionHeader = nullptr;
	}

// Write overlays if any
	PIMAGE_SECTION_HEADER pLastSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(*hInputFile, IMAGE_SIZEOF_SECTION_HEADER,
		dwFstSctHdrOffset + IMAGE_SIZEOF_SECTION_HEADER * (pNtHeader->FileHeader.NumberOfSections - 1));
	DWORD overlaySize;
	BYTE* overlay = ExtractOverlays(*hInputFile, pLastSectionHeader, &overlaySize);
	if (overlay != nullptr && overlaySize != 0)
	{
		WriteDataToFile(outputFile, pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData, overlaySize, overlay);
	}

	outputFile.close();
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