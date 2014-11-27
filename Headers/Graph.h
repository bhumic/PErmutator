#pragma once
#include "PEFunctions.h"
#include "Node.h"

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
	void AddNode(Node* node, DWORD offsetParent);

// Return a Node based on offset. The search starts from 
// the Node labeled current(argument)
	Node* FindNode(Node* current, DWORD offset);

private:
	Node* root;
};