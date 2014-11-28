#pragma once
#include "PEFunctions.h"
#include <vector>

class Node
{
public:
	Node();
	~Node();

// Add new Node as a child to the current Node
	void AppendChild(Node* child);

// Find a child Node based on offset value.
// Every Node has an unique offset
	Node* FindChild(DWORD offset);

// Getters and setters
	DWORD GetOffset();
	BYTE* GetInstructions();
	std::vector<Node* > GetChildren();
	void SetEnd(BOOL value);
	void SetOffset(DWORD offset);
	void SetInstructions(BYTE* instructions, DWORD size);
private:
	DWORD dwOffset;
	DWORD dwSize;
	BYTE* instructions;
	BOOL end;
	std::vector<Node* > children;
};

