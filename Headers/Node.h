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

#pragma once
#include "PEFunctions.h"
#include <vector>

class Node
{
public:
	Node();
	~Node();

// Add new Node as a child to the current Node
	int AppendChild(Node* child);

// Find a child Node based on offset value.
// Every Node has an unique offset
	Node* FindChild(DWORD offset);

// Getters and setters
	DWORD GetOffset();
	BYTE* GetInstructions();
	DWORD GetSize();
	std::vector<Node* > GetChildren();
	void SetEnd(BOOL value);
	void SetOffset(DWORD offset);
	void SetInstructions(BYTE* instructions, DWORD size);

// Operators
	bool operator==(const Node& node);
private:
	DWORD dwOffset;
	DWORD dwSize;
	BYTE* instructions;
	BOOL end;
	std::vector<Node* > children;
};

