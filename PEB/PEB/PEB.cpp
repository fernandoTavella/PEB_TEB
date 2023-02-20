// PEB.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

//https://www.ired.team/offensive-security/code-injection-process-injection/finding-kernel32-base-and-function-addresses-in-shellcode
//https://devdojo.com/bharat_kale/peb_malware_techniques
//TEB->PEB->Ldr->InMemoryOrderLoadList->currentProgram->ntdll->kernel32.BaseDll
int main() {
	PPEB my_peb = 0;
	PLIST_ENTRY ple = 0;
	PLDR_DATA_TABLE_ENTRY kernel32_dataTable = 0;
	//const char* function_to_find = "GetProcAddress";
	const char* function_to_find = "LoadLibraryA";
	#ifdef _WIN64
		my_peb = (PPEB)__readgsdword(0x60);
	#else
		my_peb = (PPEB)__readfsdword(0x30);
	#endif 
	// 	   _PEB_LDR_DATA
	//			0x0C InLoadOrderModuleList
	//			0x14 InMemoryOrderModuleList
	ple = &(my_peb->Ldr->InMemoryOrderModuleList);
	kernel32_dataTable = (PLDR_DATA_TABLE_ENTRY)(ple->Flink->Flink->Flink - 1);
	int kernel_base_address = (int)kernel32_dataTable->DllBase;
	DWORD* pe_sig = (DWORD*)(kernel_base_address + 0x3C);
	DWORD* rva_export = (DWORD*)(*pe_sig + kernel_base_address + 0x78);
	int image_export_dir = *rva_export + kernel_base_address;
	DWORD* address_table_rva = (DWORD*)(image_export_dir + 0x1C);
	DWORD* pointer_name_table = (DWORD*)(image_export_dir + 0x20);
	DWORD* pointer_ordinal_table = (DWORD*)(image_export_dir + 0x24);
	DWORD* pointer_table_name_base = (DWORD*)(*pointer_name_table + kernel_base_address);
	DWORD* pointer_ordinal_base = (DWORD*)(*pointer_ordinal_table + kernel_base_address);
	DWORD* addres_rva_base = (DWORD*)(*address_table_rva + kernel_base_address);
	DWORD iterations = 0;
	DWORD base_address = NULL;
	int found = 0;
	while (1) {
		const char* a_function_name = (const char*)(*pointer_table_name_base + kernel_base_address);
		for (int i = 0; a_function_name[i] != 0x00; i++) {

			if (a_function_name[i] != function_to_find[i]) {
				found = 0;
				break;
			}
			else {
				found = 1;
			}
		}
		if (found) {
			break;
		}
		iterations += 0x01;
		pointer_table_name_base += 0x01;
	}
	DWORD rva_of_func = NULL;
	__asm {
		mov eax,iterations
		mov ecx,pointer_ordinal_base
		mov edx,addres_rva_base
		mov ax,[ecx+eax*2]
		mov eax,[edx+eax*4]
		mov rva_of_func,eax
	}
	DWORD* func_addr = (DWORD*)(kernel_base_address + rva_of_func);
	return 0;
}