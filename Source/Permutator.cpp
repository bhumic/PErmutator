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

	// Create Graph
	_CreateGraph(sectionData, 0, dwSectionSize, 0);

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

void Permutator::_CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset)
{
	_DecodeResult res;
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = blockOffset;
	_OffsetType offsetEnd;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int i;
	std::string mnemonic;

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
		}

		// Main part of graph creation
		offsetEnd = decodedInstructions[i].offset;
		DWORD blockSize = offsetEnd + decodedInstructions[i].size - offset;
		Node* node = new Node();

		node->SetOffset(offset);
		node->SetInstructions(sectionData, blockSize);
		graph.AddNode(node, parentOffset);

		if (mnemonic.compare("RET") == 0 ||
			mnemonic.compare("RETN") == 0)
			return;

		int newOffset = std::stoi(reinterpret_cast<char*>(decodedInstructions[i].operands.p), nullptr, 0);

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

