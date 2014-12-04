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
	free(instructions);
	children.clear();
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

int Node::AppendChild(Node* child)
{
// Check if file alredy exists. Loop removal
	for (std::vector<Node* >::iterator it = children.begin(); it != children.end(); ++it)
	{
		if ((**it).dwOffset == child->dwOffset)
			return 1;
	}

	children.push_back(child);
	return 0;
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

bool Node::operator==(const Node& node)
{
	if (this->dwOffset == node.dwOffset)
		return true;

	return false;
}