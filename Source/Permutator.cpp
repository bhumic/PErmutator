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
	_DecodeResult res;
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = 0;
	PIMAGE_SECTION_HEADER *pSectionHeader = nullptr;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];

	PIMAGE_SECTION_HEADER ppSectionHeader;
	pSectionHeader = &ppSectionHeader;

	sectionData = LoadExecutableSection(*hInputFile, pDosHeader, pNtHeader, dwFstSctHdrOffset, pSectionHeader);

	if (sectionData == nullptr)
		return;

	DWORD dwSectionSize = (*pSectionHeader)->SizeOfRawData;

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

