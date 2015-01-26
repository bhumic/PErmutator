#ifdef _WIN32
	#include "Graph.h"
#elif __linux__
	#include "../Headers/Graph.h"
#endif


Graph::Graph()
{
	root = nullptr;
}

Graph::~Graph()
{
	free(root);
}

Node* Graph::GetRoot()
{
	return root;
}

int Graph::AddNode(Node* node, DWORD offsetParent)
{
	if (root == nullptr)
	{
		root = node;
		return 0;
	}

	Node* parent = FindNode(root, offsetParent);
	if (parent == nullptr)
		return 2;	// Error code

	return parent->AppendChild(node);
}

void Graph::AddFunctionOffset(QWORD dwCallOffset, QWORD dwOffset)
{
	FunctionAddress fa;
	fa.dwCallOffset = dwCallOffset;
	fa.dwOffset = dwOffset;

	offsets.push_back(fa);
}

Node* Graph::FindNode(Node* current, DWORD offset)
{
	if (current->GetOffset() == offset)
		return current;

	std::vector<Node* > children = current->GetChildren();
	int numOfChildren = children.size();
	
	for (int i = 0; i < numOfChildren; ++i)
	{
		Node* tmp = children.at(i);
		Node* result = FindNode(tmp, offset);
		
		if (result == nullptr)
			continue;
		else
			return result;
	}

	return nullptr;
}