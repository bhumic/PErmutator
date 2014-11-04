PErmutator
==========
The goal of this project is to create a permutation engine for PE files. The engine should randomize the executable parts of the
file. By doing this the byte pattern of the file will change but the program should execute normaly. This feature will be tested
on Windows systems to see if that kind of PE file obfuscation could increase the security aspects of the system (primarly ASLR).
In the current version of the project only the disassembler feature is implemented. You can run the program by specifying the 
path to a valid PE file which You want to disassemble.

Disassembler
===========
For disassembling purposes, the distorm disassembler library for x86/AMD64 was used (https://code.google.com/p/distorm/).
Keep that in mind because for the program to work properly you must put the distorm static library file (distorm.lib on
Windows and distorm3.a on Linux) and header file in the project root folder. The precompiled version of the library file for
Windows is included in the download but to keep the project up to date you can build the library for yourself following the
instructions on the web page given above.

Windows build
=============
This project was created using Visual Studio 2013 and all the needed files for building and adding the project to Visual Studio
are included.

Linux build
===========
To build and run the project under Linux, you need to get the valid distorm library file. To do this download the project ZIP
from https://code.google.com/p/distorm/downloads/list, extract it and under folder distorm3/make/linux run the Makefile. 
This will produce the valid static library file "distorm3.a" which you need to put in the folder with all the .cpp and .h 
files from the PErmutator project. The Makefile from PErmutator project should also be in the same directory so just run the 
"make" command and you should get the valid PErmutator executable to run on Linux.
