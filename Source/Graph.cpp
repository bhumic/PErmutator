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

#include "Graph.h"

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
