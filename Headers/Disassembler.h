// Main class for the disassembler. This class contains methods which are used
// to obtain the opcodes and mnemonics for the executable section of a PE file.


#pragma once
#include "PEFunctions.h"
#include "distorm.h"

#ifdef _WIN32
	#pragma comment(lib, "Lib\\distorm.lib")
#endif

#define MAX_INSTRUCTIONS_DISASM (1000)

class Disassembler
{
public:
	Disassembler(std::fstream& hInputFile);
	~Disassembler();

//	*A function which takes a pointer to _DecodedInst structure which at the 
//	end contains all the decoded instructions. The function returns the number
//	of decoded instructions
	void Disassemble(_DecodedInst* decodedInstructions);
	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_NT_HEADERS GetNtHeader();
private:
	std::fstream* hInputFile;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	DWORD dwFstSctHdrOffset;

//	Init the disassembler by loading the DOS and PE headers and obtaining the offset
//	To the first section header.
	void InitDisassembler();
};

