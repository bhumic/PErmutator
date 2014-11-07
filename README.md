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

Builds
======
The project can be compiled and runned on both Windows and Linux operating systems. To build the project on Windows, simply open the project in Visual Studio and build it.
For Linux, an appropriate Makefile has been added. Simply fork the project and run the added Makefile. Keep in mind that the program only disassembles PE files for now. Other file formats (including ELF) will be added later.
