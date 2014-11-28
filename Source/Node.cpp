#ifdef _WIN32
	#include "Node.h"
#elif __linux__
	#include "../Headers/Node.h"
#endif

Node::Node()
{

}

Node::~Node()
{

}

DWORD Node::GetOffset()
{
	return dwOffset;
}

BYTE* Node::GetInstructions()
{
	return instructions;
}

std::vector<Node* > Node::GetChildren()
{
	return children;
}

void Node::AppendChild(Node* child)
{
	children.push_back(child);
}

Node* Node::FindChild(DWORD offset)
{
	int numOfChildren = children.size();

	for (int i = 0; i < numOfChildren; ++i)
	{
		Node* tmp = children.at(i);
		if (tmp->dwOffset == offset)
			return tmp;
	}

	return nullptr;
}

void Node::SetEnd(BOOL value)
{
	end = value;
}

void Node::SetOffset(DWORD offset)
{
	dwOffset = offset;
}

void Node::SetInstructions(BYTE* instructions, DWORD size)
{
	this->instructions = (BYTE*)malloc(size);
	this->dwSize = size;
	std::memcpy((BYTE*)this->instructions, (BYTE*)instructions, size);
}