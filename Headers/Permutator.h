#pragma once
#include "PEFunctions.h"
#include "Graph.h"
#include "distorm.h"
#include <vector>
#include <sstream>

#ifdef _WIN32
#pragma comment(lib, "Lib\\distorm.lib")
#endif

#define MAX_INSTRUCTIONS (100)

class Permutator
{
public:
	Permutator(std::fstream& hInputFile);
	~Permutator();

	void CreateGraph();
	bool VisualizeGraph();

private:
	std::fstream* hInputFile;
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	DWORD dwFstSctHdrOffset;
	Graph graph;
		
	void InitPermutator();
	void _CreateGraph(BYTE* sectionData, _OffsetType blockOffset, DWORD dwSectionSize, _OffsetType parentOffset);
	bool IsJump(std::string mnemonic);
	bool IsRegister(std::string operand);
	bool IsFunctionOperandValid(std::string operand);
	void ProcessNode(Node* n, std::ofstream& gvFile);
	void CreatePath(Node* n, std::ofstream& gvFile);
};

