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

void Graph::AddNode(Node* node, DWORD offsetParent)
{
	if (root == nullptr)
	{
		root = node;
		return;
	}

	Node* parent = FindNode(root, offsetParent);
	if (parent == nullptr)
		return;

	parent->AppendChild(node);
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