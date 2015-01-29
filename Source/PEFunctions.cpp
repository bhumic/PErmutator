#ifdef _WIN32
	#include "PEFunctions.h"
#elif __linux__
	#include "../Headers/PEFunctions.h"
#endif

void OpenFile(const char *fileName, std::fstream& hFile)
{
	hFile.open(fileName, std::ios::in | std::ios::binary);
}
BYTE* LoadSection(std::fstream& hFile, PIMAGE_SECTION_HEADER pSectionHeader)
{
	unsigned char *buffer;

	buffer = (unsigned char *)malloc(pSectionHeader->SizeOfRawData);
	hFile.seekg(pSectionHeader->PointerToRawData, std::ios::beg);

	hFile.read((char *) buffer, pSectionHeader->SizeOfRawData);

	return buffer;
}
BOOL WriteSection(std::ofstream& hFile, PIMAGE_SECTION_HEADER pSectionHeader, unsigned char *buffer)
{
	hFile.seekp(pSectionHeader->PointerToRawData, std::ios::beg);
	hFile.write((char*) buffer, pSectionHeader->SizeOfRawData);

	return TRUE;
}
LPVOID ReadHeader(std::fstream& hFile, DWORD dwHeaderSize, DWORD dwOffset)
{
	LPVOID pHeader;

	pHeader = malloc(dwHeaderSize);
	if (pHeader == nullptr)
	{
		return nullptr;
	}

	hFile.seekg(dwOffset, std::ios::beg);
	hFile.read((char*) pHeader, dwHeaderSize);

	return pHeader;
}
PIMAGE_SECTION_HEADER FindSection(std::fstream hFile, DWORD dwRVA, DWORD dwFstSectionHeader, WORD wNumSections)
{
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	for (WORD i = 0; i < wNumSections; ++i)
	{
		pSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hFile, IMAGE_SIZEOF_SECTION_HEADER, dwFstSectionHeader + i*IMAGE_SIZEOF_SECTION_HEADER);
		if (pSectionHeader == NULL)
		{
			return nullptr;
		}

		if ((dwRVA >= pSectionHeader->VirtualAddress) &&
			(dwRVA < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize)))
		{
			return pSectionHeader;
		}

		free(pSectionHeader);
	}

	return nullptr;
}
DWORD AlignUp(DWORD dwSize, DWORD dwAlign)
{
	return ((dwSize + dwAlign - 1) - (dwSize + dwAlign - 1) % dwAlign);
}
BYTE* ReadData(unsigned char*buffer, DWORD dwOffset, DWORD dwSize)
{
	unsigned char *data_segment;

	data_segment = (unsigned char*)malloc(sizeof(unsigned char)* dwSize);
	memset(data_segment, 0, dwSize);
	if (data_segment == nullptr)
	{
		return nullptr;
	}

/*#ifdef _WIN32
	memcpy_s(data_segment, dwSize, buffer + dwOffset, dwSize);
#elif __linux__
	memcpy(data_segment, buffer + dwOffset, dwSize);
#else
#error "OS not supported!"
#endif*/
	std::memcpy(data_segment, buffer + dwOffset, dwSize);

	return data_segment;
}
BOOL IsFunctionName(char *buffer)
{
	DWORD length = strlen(buffer);

	for (DWORD i = 0; i < length; ++i)
	{
		if ((buffer[i] >= 65 && buffer[i] <= 90) ||
			(buffer[i] >= 97 && buffer[i] <= 122))
		{
			continue;
		}
		else
		{
			return FALSE;
		}
	}

	return TRUE;
}
BOOL WriteSectionHeader(PIMAGE_SECTION_HEADER pSectionHeader, DWORD dwSectionID, std::ofstream& hFile, DWORD dwFstSctHeaderOffset)
{
	DWORD dwSectionOffset;

	dwSectionOffset = dwFstSctHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER*dwSectionID;
	hFile.seekp(dwSectionOffset, std::ios::beg);
	hFile.write((char*)pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	return TRUE;
}
PIMAGE_SECTION_HEADER AddSection(std::fstream& hFile, unsigned char *sectionData, DWORD dwSectionDataSize,
	DWORD dwFstSectionHeaderOffset, PIMAGE_NT_HEADERS pNtHeader, const char *sectionName)
{
	PIMAGE_SECTION_HEADER pLastSectionHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	// Read the last section header
	pLastSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hFile, IMAGE_SIZEOF_SECTION_HEADER,
		dwFstSectionHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER*(pNtHeader->FileHeader.NumberOfSections - 1));
	if (pLastSectionHeader == nullptr)
	{
		return nullptr;
	}

	// Allocate memory for new section header
	pSectionHeader = (PIMAGE_SECTION_HEADER)malloc(IMAGE_SIZEOF_SECTION_HEADER);

	// Populate the section header
#ifdef _WIN32
	memcpy_s(pSectionHeader->Name, IMAGE_SIZEOF_SHORT_NAME, sectionName, IMAGE_SIZEOF_SHORT_NAME);
#elif __linux__
	memcpy(pSectionHeader->Name, sectionName, IMAGE_SIZEOF_SHORT_NAME);
#else
#error "OS not supported"
#endif
	pSectionHeader->Misc.VirtualSize = dwSectionDataSize;
	pSectionHeader->VirtualAddress = AlignUp(pLastSectionHeader->VirtualAddress + pLastSectionHeader->Misc.VirtualSize,
		pNtHeader->OptionalHeader.SectionAlignment);
	pSectionHeader->SizeOfRawData = AlignUp(dwSectionDataSize, pNtHeader->OptionalHeader.FileAlignment);
	pSectionHeader->PointerToRawData = AlignUp(pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData,
		pNtHeader->OptionalHeader.FileAlignment);
	pSectionHeader->PointerToRelocations = 0;
	pSectionHeader->PointerToLinenumbers = 0;
	pSectionHeader->NumberOfRelocations = 0;
	pSectionHeader->NumberOfLinenumbers = 0;
	pSectionHeader->Characteristics = 0xE0000020;

	// Position the file pointer where the new section header should be written
	hFile.seekg(dwFstSectionHeaderOffset + IMAGE_SIZEOF_SECTION_HEADER*pNtHeader->FileHeader.NumberOfSections, std::ios::beg);

	// Write the new section header
	hFile.write((char*)pSectionHeader, IMAGE_SIZEOF_SECTION_HEADER);

	// Position the file pointer to where the section data should be written
	hFile.seekg(pSectionHeader->PointerToRawData, std::ios::beg);

	// Write the section data
	hFile.write((char*)sectionData, pSectionHeader->SizeOfRawData);

	// Update the PE header
	pNtHeader->FileHeader.NumberOfSections++;
	pNtHeader->OptionalHeader.SizeOfImage = AlignUp(pNtHeader->OptionalHeader.SizeOfImage + pSectionHeader->Misc.VirtualSize,
		pNtHeader->OptionalHeader.SectionAlignment);

	return pSectionHeader;
}
BOOL WriteDataToFile(std::ofstream& hFile, DWORD dwOffset, DWORD dwSize, BYTE* data)
{
	hFile.seekp(dwOffset, std::ios::beg);
	hFile.write((char*) data, dwSize);

	return TRUE;
}
BYTE* LoadExecutableSection(std::fstream& hFile, PIMAGE_DOS_HEADER pDosHeader, PIMAGE_NT_HEADERS pNtHeader,
	DWORD dwFstSctHdrOffset, PIMAGE_SECTION_HEADER* pSectionHeader)
{
	BYTE* sectionData = nullptr;
	//PIMAGE_SECTION_HEADER pSectionHeader = nullptr;

	for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
	{
		*pSectionHeader = (PIMAGE_SECTION_HEADER)ReadHeader(hFile, IMAGE_SIZEOF_SECTION_HEADER, dwFstSctHdrOffset + i*IMAGE_SIZEOF_SECTION_HEADER);
		if (pSectionHeader == nullptr)
		{
			return nullptr;
		}

		//if (((*pSectionHeader)->Characteristics & 0x00000020) && ((*pSectionHeader)->Characteristics & 0x20000000))
		//{
			if ((pNtHeader->OptionalHeader.AddressOfEntryPoint >= (*pSectionHeader)->VirtualAddress) &&
				(pNtHeader->OptionalHeader.AddressOfEntryPoint < ((*pSectionHeader)->VirtualAddress + (*pSectionHeader)->Misc.VirtualSize)))
			{
				break;
			}
		//}

		free(*pSectionHeader);
		*pSectionHeader = nullptr;
	}

	if (*pSectionHeader == nullptr)
		return nullptr;
	sectionData = LoadSection(hFile, *pSectionHeader);

	return sectionData;
}
BOOL ValidateFile(std::fstream& hFile)
{
	BYTE buffer[2];

	hFile.read((char*)buffer, 2);

	if (buffer[0] != 'M' || buffer[1] != 'Z')
		return FALSE;


	return TRUE;
}
BYTE* ExtractOverlays(std::fstream& hFile, PIMAGE_SECTION_HEADER pLastSectionHeader, DWORD *overlay_size)
{
	DWORD fileSize;
	DWORD overlaySize;
	DWORD begin, end;
	unsigned char *overlayBuffer;

	// Get the file size
	hFile.seekg(0, std::ios::beg);
	begin = (DWORD)hFile.tellg();
	hFile.seekg(0, std::ios::end);
	end = (DWORD)hFile.tellg();
	fileSize = end - begin;

	// Position where the overlay starts
	DWORD overlayStart = pLastSectionHeader->PointerToRawData + pLastSectionHeader->SizeOfRawData;

	// Check if the overlay exists
	if (overlayStart == fileSize)
	{
		// NO overlay
		return nullptr;
	}

	// Position the file pointer to the beginning of overlay
	hFile.seekg(overlayStart, std::ios::beg);

	// Calculate overlay size and allocate memory for buffer
	overlaySize = fileSize - overlayStart;
	overlayBuffer = (unsigned char *)malloc(overlaySize * sizeof(unsigned char));
	if (overlayBuffer == NULL)
	{
		std::cout << "Overlay: Insufficient memory for overlay buffer!" << std::endl;
		std::cout << "----------------------------------------" << std::endl;
		return nullptr;
	}

	// Read the overlay into the buffer
	hFile.read((char*)overlayBuffer, overlaySize);
	*overlay_size = overlaySize;

	return overlayBuffer;
}