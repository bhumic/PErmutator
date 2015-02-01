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

#pragma once
#include "PEFunctions.h"
#include "Graph.h"
#include "distorm.h"
#include <vector>
#include <queue>
#include <sstream>

#ifdef _WIN32
#pragma comment(lib, "Lib\\distorm.lib")
#endif

#define MAX_INSTRUCTIONS (100)

typedef struct _Block
{
	_OffsetType offset;
	_OffsetType parentOffset;
	DWORD blockSize = 0;
} Block;

class Permutator
{
public:
	Permutator(std::fstream& hInputFile);
	~Permutator();

	Graph* GetGraph();

	int CreateGraph(int creationMode);
	bool VisualizeGraph(Node* n);
	bool WriteModifiedFile();

private:
	std::fstream* hInputFile;
	std::ofstream outputFile;
	std::ofstream gvFile;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	DWORD dwFstSctHdrOffset;
	Graph graph;
	std::vector<Node* > dataNodes;
	BYTE* dataBytes;
	DWORD dataSize;
		
	void InitPermutator();
	void _CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset, 
		std::vector<Block>& targets);
	void __CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset);
	bool CheckRange(QWORD qOffset);
	bool IsJump(std::string mnemonic);
	bool IsRegister(std::string operand);
	bool IsFunctionOperandValid(std::string operand);
	void ProcessNode(Node* n, std::ofstream& gvFile);
	void CreatePath(Node* n, std::ofstream& gvFile);
	void CreateDataNodes(BYTE* sectionData);
	void WriteGraph(Node* n, BYTE* sectionData);
	void WriteData(BYTE* sectionData);
};

