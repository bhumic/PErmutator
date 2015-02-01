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

Disassembler::Disassembler(std::fstream& hInputFile)
{
	this->hInputFile = &hInputFile;
	InitDisassembler();
}

Disassembler::~Disassembler()
{
	free(pDosHeader);
	free(pNtHeader);
}

void Disassembler::InitDisassembler()
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

void Disassembler::Disassemble(_DecodedInst* decodedInstructions)
{
	BYTE* sectionData = nullptr;
	_DecodeResult res;
	//_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0, next;
	_DecodeType dt = Decode32Bits;
	_OffsetType offset = 0;
	PIMAGE_SECTION_HEADER *pSectionHeader = nullptr;
	
	PIMAGE_SECTION_HEADER ppSectionHeader;
	pSectionHeader = &ppSectionHeader;

	sectionData = LoadExecutableSection(*hInputFile, pDosHeader, pNtHeader, dwFstSctHdrOffset, pSectionHeader);

	if (sectionData == nullptr)
		return;

	DWORD dwSectionSize = (*pSectionHeader)->SizeOfRawData;
	
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
