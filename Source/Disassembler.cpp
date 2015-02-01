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

#include "Disassembler.h"

Disassembler::Disassembler(char* fileName)
{
	hInputFile.exceptions(std::fstream::badbit | std::fstream::failbit);
	InitDisassembler(fileName);
}

Disassembler::~Disassembler()
{
	free(pDosHeader);
	free(pNtHeader);
}

void Disassembler::InitDisassembler(char* fileName)
{
	try
	{
		hInputFile.open(fileName, std::ios::in | std::ios::binary);
	}
	catch (std::fstream::failure e)
	{
		std::cerr << "InitDisassembler: Error while opening input file: " << e.what() << std::endl;
		exit(-1);
	}

	if (!ValidateFile(hInputFile))
	{
		std::cerr << "InitDisassembler: Not a valid PE file (MZ signature)" << std::endl;
		exit(-1);
	}

	// Read the DOS header
	pDosHeader = (PIMAGE_DOS_HEADER)ReadHeader(hInputFile, sizeof(IMAGE_DOS_HEADER), 0);
	if (pDosHeader == nullptr)
	{
		std::cerr << "InitDisassembler: Invalid DOS header" << std::endl;
		exit(-1);
	}

	// Read the PE Header
	pNtHeader = (PIMAGE_NT_HEADERS)ReadHeader(hInputFile, sizeof(IMAGE_NT_HEADERS), pDosHeader->e_lfanew);
	if (pNtHeader == nullptr)
	{
		std::cerr << "InitDisassembler: Invalid NT header" << std::endl;
		exit(-1);
	}

	// Find the file offset to the first section header
	dwFstSctHdrOffset = pDosHeader->e_lfanew + 4 + IMAGE_SIZEOF_FILE_HEADER + pNtHeader->FileHeader.SizeOfOptionalHeader;
}

void Disassembler::Disassemble(_DecodedInst* decodedInstructions)
{
	BYTE* sectionData = nullptr;
	_DecodeResult res;
	//_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = 0;
	
	pExecSectionHeader = FindSection(hInputFile, pNtHeader->OptionalHeader.AddressOfEntryPoint, dwFstSctHdrOffset,
		pNtHeader->FileHeader.NumberOfSections);
	if (pExecSectionHeader == nullptr)
	{
		std::cerr << "CreateGraph: Unable to read section header for executable code" << std::endl;
		exit(-1);
	}

	sectionData = LoadSection(hInputFile, pExecSectionHeader);
	if (sectionData == nullptr)
		return;

	DWORD dwSectionSize = pExecSectionHeader->SizeOfRawData;
	
	while (1)
	{
		res = distorm_decode(offset, (const unsigned char*)sectionData, dwSectionSize,
			dt, decodedInstructions, MAX_INSTRUCTIONS_DISASM, &decodedInstructionsCount);
		if (res == DECRES_INPUTERR)
		{
			free(sectionData);
			return;
		}

		for (DWORD i = 0; i < decodedInstructionsCount; ++i)
		{
			std::cout << std::hex << std::setw(8) << std::setfill('0') << decodedInstructions[i].offset << " " <<
				std::setw(20) << std::setfill(' ') << decodedInstructions[i].instructionHex.p << " " <<
				decodedInstructions[i].mnemonic.p << " " <<
				(decodedInstructions[i].operands.length != 0 ? " " : "") <<
				decodedInstructions[i].operands.p << std::endl;
		}

		if (res == DECRES_SUCCESS) break; // All instructions were decoded.
		else if (decodedInstructionsCount == 0) break;

		// Synchronize:
		next = (unsigned long)(decodedInstructions[decodedInstructionsCount - 1].offset - offset);
		next += decodedInstructions[decodedInstructionsCount - 1].size;
		// Advance ptr and recalc offset.
		sectionData += next;
		dwSectionSize -= next;
		offset += next;
	}
}

PIMAGE_DOS_HEADER Disassembler::GetDosHeader()
{
	return this->pDosHeader;
}

PIMAGE_NT_HEADERS Disassembler::GetNtHeader()
{
	return this->pNtHeader;
}
