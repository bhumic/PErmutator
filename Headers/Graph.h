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
