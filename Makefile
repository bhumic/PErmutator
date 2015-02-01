CC = gcc
CFLAGS = -Wall -fPIC -O2 -ggdb
CPPFLAGS = -IHeaders
TARGET = libdistorm3.so
COBJS = ExternalLib/distorm3/src/mnemonics.o ExternalLib/distorm3/src/wstring.o ExternalLib/distorm3/src/textdefs.o \
ExternalLib/distorm3/src/prefix.o ExternalLib/distorm3/src/operands.o ExternalLib/distorm3/src/insts.o \
ExternalLib/distorm3/src/instructions.o ExternalLib/distorm3/src/distorm.o ExternalLib/distorm3/src/decoder.o 
CFLAGS_D = -fPIC -O2 -Wall -DSUPPORT_64BIT_OFFSET -DDISTORM_STATIC

default: PErmutator

PErmutator: PEFunctions.o Disassembler.o TestMain.o Permutator.o Graph.o Node.o distorm3.a
	$(CC) $(CPPFLAGS) $(CFLAGS) -o PErmutator TestMain.o Permutator.o PEFunctions.o Disassembler.o Graph.o Node.o -lstdc++ distorm3.a
	
TestMain.o: Source/TestMain.cpp Headers/PEFunctions.h Headers/Disassembler.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c Source/TestMain.cpp -lstdc++ -std=c++11
	
Permutator.o: Source/Permutator.cpp Headers/Permutator.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c Source/Permutator.cpp -lstdc++ -std=c++11
	
PEFunctions.o: Source/PEFunctions.cpp Headers/PEFunctions.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c Source/PEFunctions.cpp -lstdc++ -std=c++11
	
Disassembler.o: Source/Disassembler.cpp Headers/Disassembler.h Headers/distorm.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c Source/Disassembler.cpp -lstdc++ -std=c++11

Graph.o: Source/Graph.cpp Headers/Graph.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c Source/Graph.cpp -lstdc++ -std=c++11

Node.o: Source/Node.cpp Headers/Node.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c Source/Node.cpp -lstdc++ -std=c++11
	
distorm3.a: ${COBJS}
	${CC} ${CFLAGS} ${VERSION} ${COBJS} -shared -o ${TARGET}
	ar rs distorm3.a ${COBJS}

clean:
	rm -rf PErmutator *.o ExternalLib/distorm3/src/*.o *.so *.a graph.dot permutatedFile.exe
