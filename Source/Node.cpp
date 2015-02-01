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

#include "Node.h"

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

DWORD Node::GetSize()
{
	return dwSize;
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
