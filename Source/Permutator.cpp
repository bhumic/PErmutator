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

void Permutator::CreateGraph()
{
	BYTE* sectionData = nullptr;
	PIMAGE_SECTION_HEADER *pSectionHeader = nullptr;

	PIMAGE_SECTION_HEADER ppSectionHeader;
	pSectionHeader = &ppSectionHeader;

	sectionData = LoadExecutableSection(*hInputFile, pDosHeader, pNtHeader, dwFstSctHdrOffset, pSectionHeader);

	if (sectionData == nullptr)
		return;

	DWORD dwSectionSize = (*pSectionHeader)->SizeOfRawData;

	// Calculate entry point offset
	DWORD dwEpOffset = pNtHeader->OptionalHeader.AddressOfEntryPoint - 
		(*pSectionHeader)->VirtualAddress;

	// Create Graph
	_CreateGraph(sectionData + dwEpOffset, dwEpOffset, dwSectionSize, 0);

	return;
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
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = blockOffset;
	_OffsetType offsetEnd;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int i;
	DWORD tmpOffset = blockOffset;
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
				mnemonic.compare("RETN") == 0)
			{
				break;
			}

			if (mnemonic.compare("CALL") == 0)
			{
				std::string functionOperand = reinterpret_cast<char*> (decodedInstructions[i].operands.p);
				if (IsRegister(functionOperand) || !IsFunctionOperandValid(functionOperand))
					continue;

				int functionOffset = std::stoll(functionOperand, nullptr, 0);
				graph.AddFunctionOffset(tmpOffset, functionOffset - tmpOffset);
			}

			tmpOffset += decodedInstructions[i].size;
		}

		// Main part of graph creation
		offsetEnd = decodedInstructions[i].offset;
		DWORD blockSize = offsetEnd + decodedInstructions[i].size - offset;
		Node* node = new Node();

		node->SetOffset(offset);
		node->SetInstructions(sectionData, blockSize);
		
		if (graph.AddNode(node, parentOffset))
		{
			return;
		}

		if (mnemonic.compare("RET") == 0 ||
			mnemonic.compare("RETN") == 0)
			return;

		operand = reinterpret_cast<char*>(decodedInstructions[i].operands.p);
		operand.resize(decodedInstructions[i].operands.length);
		if (IsRegister(operand))
			return;

		int newOffset = std::stoll(operand, nullptr, 0);

		_CreateGraph(sectionData + blockSize + (newOffset - offsetEnd - decodedInstructions[i].size),
					 newOffset,
					 dwSectionSize - newOffset + offset,
					 node->GetOffset());

		if (mnemonic.compare("JMP") == 0)
			return;

		int jumpFalseOffset = offsetEnd + decodedInstructions[i].size;
		
		_CreateGraph(sectionData + jumpFalseOffset - offset,
			jumpFalseOffset,
			dwSectionSize - jumpFalseOffset + offset,
			node->GetOffset());

		break;
	}
}

bool Permutator::VisualizeGraph()
{
	std::ofstream gvFile ("graph.gh");

	std::string digraphStart = "digraph g {\n"
		"graph [fontsize=12 labelloc=\"t\" label=\"\" splines=true overlap=false];\n"
		"ratio = auto;\n";
	std::string digraphEnd = "}";
	gvFile.write(digraphStart.c_str(), digraphStart.length());
	
	Node* n = graph.GetRoot();

	ProcessNode(n, gvFile);
	CreatePath(n, gvFile);

	gvFile.write(digraphEnd.c_str(), digraphEnd.length());
	gvFile.close();
	return true;
}

void Permutator::ProcessNode(Node* n, std::ofstream& gvFile)
{
	_DecodeResult res;
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = 0;
	_OffsetType offsetEnd;
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

		for (int i = 0; i < decodedInstructionsCount; ++i)
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

	for (int i = 0; i < n->GetChildren().size(); ++i)
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

	for (int i = 0; i < n->GetChildren().size(); ++i)
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