#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include <stdint.h>


PVOID pNTDT= nullptr;	//Address of NtDrawText
PVOID pNTDTOffset_8 = nullptr;	//Address of NtDrawText+0x8
uint32_t ntqip_ssn = 0x0;	//SSN for NtQueryInformationProcess

//Define custom function prototype for NtQueryInformationProcess
typedef NTSTATUS (NTAPI* fnNtQueryInformationProcess)(HANDLE ProcessHandle,PROCESSINFOCLASS ProcessInformationClass,PVOID ProcessInformation,ULONG ProcessInformationLength,PULONG ReturnLength);


uint32_t ROR13(uint32_t functionHash, int bits) {
	return ((functionHash >> bits) | (functionHash << (32 - bits))) & 0xFFFFFFFF;
}

uint32_t ROR13Hash(const char* functionName) {
	uint32_t functionHash = 0;
	for (int i = 0; functionName[i] != '\0'; i++) {
		uint32_t c = (uint32_t)functionName[i];
		functionHash = ROR13(functionHash, 13);
		functionHash = functionHash + c;
	}
	return functionHash;
}

//Get module handle for ntdll and kernel32 at the same time
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

//Return function's address by function name hash
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
			return pFunctionAddress;
		}
	}
	return NULL;
}

//Convert RVA to File Offset when handling PE file saved in an array
DWORD RvaToFileOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
	PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++) {
		DWORD sectionSize = sectionHeader->Misc.VirtualSize;
		DWORD sectionAddress = sectionHeader->VirtualAddress;
		if (rva >= sectionAddress && rva < sectionAddress + sectionSize) {
			return rva - sectionAddress + sectionHeader->PointerToRawData;
		}
	}
	return 0; 
}


//Similar to GetFuncByHash, but return the function's SSN. Only support NTAPI
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
	return 0x0;
}


//Hardware breakpoint related code is shamelessly copied from https://gist.github.com/CCob/fe3b63d80890fafeca982f76c8a3efdf
unsigned long long setBits(unsigned long long dw, int lowBit, int bits, unsigned long long newValue) 
{
	unsigned long long mask = (1UL << bits) - 1UL;
	dw = (dw & ~(mask << lowBit)) | (newValue << lowBit);
	return dw;
}

void clearBreakpoint(CONTEXT& ctx, int index) 
{
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


void clearHardwareBreakpoint(CONTEXT* ctx, int index) 
{
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

//Update the SSN stored in RAX
void setResult(CONTEXT* ctx, ULONG_PTR result)
{
	printf("Before updating: RAX = 0x%x\n\n", ctx->Rax);
	ctx->Rax = result;
	//printf("RAX is updated to 0x18\n");
	printf("After updating: RAX = 0x%x\n\n", ctx->Rax);
}

LONG WINAPI exceptionHandler(PEXCEPTION_POINTERS exceptions) 
{
	if (exceptions->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP &&
		exceptions->ExceptionRecord->ExceptionAddress == pNTDTOffset_8) 
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
	HANDLE hExHandler = AddVectoredExceptionHandler(1, exceptionHandler);
	CONTEXT threadCtx;
	threadCtx.ContextFlags = CONTEXT_ALL;
	if (GetThreadContext((HANDLE)-2, &threadCtx)) 
	{
		enableBreakpoint(threadCtx, pNTDTOffset_8, 0);	//Set a hardware breakpoint at NtDrawText+0x8
		SetThreadContext((HANDLE)-2, &threadCtx);
	}
	return hExHandler;
}




int main()
{
	HMODULE ntdll;
	HMODULE kernel32;
	GetModule(&ntdll, &kernel32);
	printf("ntdll base address: %p\n\n", ntdll);
	printf("kernel32 base address: %p\n\n", kernel32);

	pNTDT = GetFuncByHash(ntdll, 0xA1920265);	//NtDrawText hash
	pNTDTOffset_8 = (PVOID)((BYTE*)pNTDT + 0x8);	//Offset 0x8 from NtDrawText

	//Read ntdll on disk, and save the content in an array
	HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("[!] CreateFileA Failed With Error : %d \n\n", GetLastError());
		return -1;
	}
	DWORD dwFileLen = GetFileSize(hFile, NULL);
	DWORD dwNumberOfBytesRead;
	PVOID pNtdllBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileLen);
	if (!ReadFile(hFile, pNtdllBuffer, dwFileLen, &dwNumberOfBytesRead, NULL) || dwFileLen != dwNumberOfBytesRead) 
	{
		printf("[!] ReadFile Failed With Error : %d \n\n", GetLastError());
		printf("[i] Read %d of %d Bytes \n\n", dwNumberOfBytesRead, dwFileLen);
		return -1;
	}
	if (hFile)
	{
		CloseHandle(hFile);
	}
	

	//Get NtQueryInformationProcess function address by ROR13 hash
	ntqip_ssn = GetSSNByHash(pNtdllBuffer, 0xB10FD839); 
	printf("SSN of NtQueryInformationProcess is 0x%x\n\n", ntqip_ssn);

	//Create a process to verify if NtQueryInformationProcess works later
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
	
	//Set up hardware breakpoint
	HANDLE hExHandler = setupHardwareBp(ntdll);
	
	if ( hExHandler != nullptr)
	{
		printf("Modified rax at NtDrawText+0x8(0x%p)\n\n",pNTDTOffset_8);
		//Assign the address of NtDrawText to NtQueryInformationProcess function pointer
		fnNtQueryInformationProcess pNTQIP = (fnNtQueryInformationProcess)pNTDT;
		//But prepare arguments for the hooked function such as NtQueryInformationProcess
		NTSTATUS status = pNTQIP(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);	

		if (status == 0) 
		{
			printf("NTAPI NtQueryInformationprocess was called successfully\n\nPEB of inspected process is :%p\n\n", pbi.PebBaseAddress);
		}
		else
		{
			printf("Called failed\n\n");
			return -1;
		}

		printf("The result of NTAPI NtQueryInformationProcess is %d\n\n", status);
	}

	return 0;
}

