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
	Disassembler(char* fileName);
	~Disassembler();

//	*A function which takes a pointer to _DecodedInst structure which at the 
//	end contains all the decoded instructions. The function returns the number
//	of decoded instructions
	void Disassemble(_DecodedInst* decodedInstructions);
	PIMAGE_DOS_HEADER GetDosHeader();
	PIMAGE_NT_HEADERS GetNtHeader();
private:
	std::fstream hInputFile;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pExecSectionHeader;
	DWORD dwFstSctHdrOffset;

//	Init the disassembler by loading the DOS and PE headers and obtaining the offset
//	To the first section header.
	void InitDisassembler(char* fileName);
};

