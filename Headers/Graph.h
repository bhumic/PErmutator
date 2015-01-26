#pragma once
#include "PEFunctions.h"
#include "Node.h"

typedef struct _FunctionAddress
{
	QWORD dwCallOffset;
	QWORD dwOffset;
} FunctionAddress;

class Graph
{
public:
	Graph();
	~Graph();

// Return the Node representing the root element
	Node* GetRoot();

// Add a new Node to the Graph. The new Node is added
// as a child of the Node repsented with the offsetParent 
// argument.
	int AddNode(Node* node, DWORD offsetParent);

// Return a Node based on offset. The search starts from 
// the Node labeled current(argument)
	Node* FindNode(Node* current, DWORD offset);

// Add a function offset value to the Graph. Based on
// call function argument
	void AddFunctionOffset(QWORD dwCallOffset, QWORD dwOffset);

private:
	Node* root;
	std::vector<FunctionAddress> offsets;
};