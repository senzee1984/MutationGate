#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <stdint.h>

PVOID g_ntDrawTextPtr = nullptr;
PVOID g_ntDrawTextPtroffset8 = nullptr;
uint32_t ntqip_ssn = 0x0;

typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)
(	//Define custom function prototype for NtQueryInformationProcess
	HANDLE ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID ProcessInformation,
	ULONG ProcessInformationLength,
	PULONG ReturnLength
);


uint32_t ROR13(uint32_t functionHash, int bits) 
{
	return ((functionHash >> bits) | (functionHash << (32 - bits))) & 0xFFFFFFFF;
}

uint32_t ROR13Hash(const char* functionName) 
{
	uint32_t functionHash = 0;
	for (int i = 0; functionName[i] != '\0'; i++) {
		uint32_t c = (uint32_t)functionName[i];
		functionHash = ROR13(functionHash, 13);
		functionHash = functionHash + c;
	}
	return functionHash;
}


void GetModule(HMODULE * ntdll, HMODULE * kernel32)
{
	PPEB peb = (PPEB)(__readgsqword(0x60));
	PPEB_LDR_DATA ldr = *(PPEB_LDR_DATA*)((PBYTE)peb + 0x18); //PPEB_LDR_DATA pLdr = pPeb->Ldr;

	PLIST_ENTRY ntdlllistentry= *(PLIST_ENTRY*)((PBYTE)ldr + 0x30);
	*ntdll= *(HMODULE*)((PBYTE)ntdlllistentry + 0x10);
	PLIST_ENTRY kernelbaselistentry = *(PLIST_ENTRY*)((PBYTE)ntdlllistentry);
	PLIST_ENTRY kernel32listentry = *(PLIST_ENTRY*)((PBYTE)kernelbaselistentry);
	*kernel32 = *(HMODULE*)((PBYTE)kernel32listentry + 0x10);
}

PVOID GetFuncByHash(IN HMODULE hModule, uint32_t Hash)
{
	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) 
	{
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		if (Hash == ROR13Hash(pFunctionName)) 
		{
		//	printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %x\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]+1);
			return pFunctionAddress;
		}
	}
	return NULL;
}

DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;
		DWORD sectionAddress = sectionHeader->VirtualAddress;
		if (rva >= sectionAddress && rva < sectionAddress + sectionSize) {
			return rva - sectionAddress + sectionHeader->PointerToRawData;
		}
	}
	return 0; // RVA not found in any section
}


uint32_t GetSSNByHash(PVOID pe, uint32_t Hash) 
{
	PBYTE pBase = (PBYTE)pe;
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	DWORD exportdirectory_foa = RvaToFileOffset(pImgNtHdrs, ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + exportdirectory_foa);	//Calculate corresponding offset
	PDWORD FunctionNameArray = (PDWORD)(pBase + RvaToFileOffset(pImgNtHdrs, pImgExportDir->AddressOfNames));
	PDWORD FunctionAddressArray = (PDWORD)(pBase + RvaToFileOffset(pImgNtHdrs, pImgExportDir->AddressOfFunctions));
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + RvaToFileOffset(pImgNtHdrs, pImgExportDir->AddressOfNameOrdinals));

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++)
	{
		CHAR* pFunctionName = (CHAR*)(pBase + RvaToFileOffset(pImgNtHdrs, FunctionNameArray[i]));
		DWORD Function_RVA = FunctionAddressArray[FunctionOrdinalArray[i]];
		if (Hash == ROR13Hash(pFunctionName))
		{
			//printf("[ %x ] FOUND API -\t NAME: %s -\t RVA: 0x%x  -\t ORDINAL: %x\n", i, pFunctionName, Function_RVA, FunctionOrdinalArray[i] + 1);
			void *ptr = malloc(10);
			if (ptr == NULL) {
				perror("malloc failed");
				return -1;
			}
			unsigned char byteAtOffset5 = *((unsigned char*)(pBase + RvaToFileOffset(pImgNtHdrs, Function_RVA)) + 4);
			//printf("Syscall number of function %s is: 0x%x\n", pFunctionName,byteAtOffset5);	//0x18
			free(ptr);
			return byteAtOffset5;
		}
	}
}


unsigned long long setBits(unsigned long long dw, int lowBit, int bits, unsigned long long newValue) {
	unsigned long long mask = (1UL << bits) - 1UL;
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
	return dw;
}

void clearBreakpoint(CONTEXT& ctx, int index) {
	switch (index) {
	case 0:
		ctx.Dr0 = 0;
		break;
	case 1:
		ctx.Dr1 = 0;
		break;
	case 2:
		ctx.Dr2 = 0;
		break;
	case 3:
		ctx.Dr3 = 0;
		break;
	}

	ctx.Dr7 = setBits(ctx.Dr7, (index * 2), 1, 0);
	ctx.Dr6 = 0;
	ctx.EFlags = 0;
}

void enableBreakpoint(CONTEXT& ctx, PVOID address, int index) {
	switch (index) {
	case 0:
		ctx.Dr0 = (ULONG_PTR)address;
		break;
	case 1:
		ctx.Dr1 = (ULONG_PTR)address;
		break;
	case 2:
		ctx.Dr2 = (ULONG_PTR)address;
		break;
	case 3:
		ctx.Dr3 = (ULONG_PTR)address;
		break;
	}

	ctx.Dr7 = setBits(ctx.Dr7, 16, 16, 0);
	ctx.Dr7 = setBits(ctx.Dr7, (index * 2), 1, 1);
	ctx.Dr6 = 0;
}

void clearHardwareBreakpoint(CONTEXT* ctx, int index) {
	switch (index) {
	case 0:
		ctx->Dr0 = 0;
		break;
	case 1:
		ctx->Dr1 = 0;
		break;
	case 2:
		ctx->Dr2 = 0;
		break;
	case 3:
		ctx->Dr3 = 0;
		break;
	}

	ctx->Dr7 = setBits(ctx->Dr7, (index * 2), 1, 0);
	ctx->Dr6 = 0;
	ctx->EFlags = 0;
}

void setResult(CONTEXT* ctx, ULONG_PTR result)
{
	printf("Before updating RAX: RAX is 0x%x\n", ctx->Rax);
	ctx->Rax = result;
	//printf("RAX is updated to 0x18\n");
	printf("After updating RAX: Now RAX is 0x%x\n", ctx->Rax);
}

LONG WINAPI exceptionHandler(PEXCEPTION_POINTERS exceptions) 
{
	if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		exceptions->ExceptionRecord->ExceptionAddress == g_ntDrawTextPtroffset8) 
	{
		setResult(exceptions->ContextRecord, ntqip_ssn);	//SSN for NtQueryInformationProcess
		clearHardwareBreakpoint(exceptions->ContextRecord, 0);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	else {
		return EXCEPTION_CONTINUE_SEARCH;
	}
}



HANDLE setupHardwareBp(HMODULE module) 
{
	if (g_ntDrawTextPtr == nullptr) 
	{
		g_ntDrawTextPtr = (PVOID)GetProcAddress(module, "NtDrawText");
		g_ntDrawTextPtroffset8 = (PVOID)((BYTE*)g_ntDrawTextPtr + 0x8);
	}
	if (g_ntDrawTextPtr == nullptr)
	{
			return nullptr;
	}

	HANDLE hExHandler = AddVectoredExceptionHandler(1, exceptionHandler);

	CONTEXT threadCtx;
	threadCtx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext((HANDLE)-2, &threadCtx)) 
	{
		enableBreakpoint(threadCtx, g_ntDrawTextPtroffset8, 0);
		SetThreadContext((HANDLE)-2, &threadCtx);
	}
	return hExHandler;
}


int main()
{
	HMODULE ntdll;
	HMODULE kernel32;
	GetModule(&ntdll, &kernel32);
	printf("ntdll base address: %p\n", ntdll);
	printf("kernel32 base address: %p\n", kernel32);
	printf("Address of function is %p\n\n",GetFuncByHash(kernel32, 0xec0e4e8e));	//LoadLibraryA

	HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// allocating enough memory to read the ntdll.dll file
	DWORD dwFileLen = GetFileSize(hFile, NULL);
	DWORD dwNumberOfBytesRead;
	PVOID pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);

	// reading the file
	if (!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead) 
	{
		printf("[!] ReadFile Failed With Error : %d \n", GetLastError());
		printf("[i] Read %d of %d Bytes \n", dwNumberOfBytesRead, dwFileLen);
		return -1;
	}

	if (hFile)
	{
		CloseHandle(hFile);
	}
	
	ntqip_ssn = GetSSNByHash(pNtdllBuffer, 0xB10FD839); //NtQueryInformationProcess
	printf("SSN of NtQueryInformationProcess is 0x%x\n", ntqip_ssn);

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcessA("C:\\Windows\\system32\\calc.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
		printf("CreateProcess failed (%d).\n", GetLastError());
		return 1;
	}
  
	PROCESS_BASIC_INFORMATION pbi;
	HANDLE hExHandler = setupHardwareBp(ntdll);
	if ( hExHandler != nullptr)
	{
		printf("Modified rax at NtDrawText+0x8(0x%p)\n",g_ntDrawTextPtroffset8);
		fnNtQueryInformationProcess pNTQIP = (fnNtQueryInformationProcess)g_ntDrawTextPtr;
		NTSTATUS status = pNTQIP(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);	//But prepare arguments for the hooked function

		if (status == 0) 
		{
			printf("PEB Address:%p\n", pbi.PebBaseAddress);
		}
		else
		{
			printf("\nCalled failed\n");
		}
		printf("\nThe result of NT function is %d\n", status);
	}
	return 0;
}

