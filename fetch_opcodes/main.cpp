#include <Windows.h>
#include <string>
#include <fstream>

uint32_t namingAddress = 0;
HMODULE thisDll;

std::string GetOpCodeName(uint32_t op) {
	uint32_t pointer = 0;

	_asm {
		push op
		call namingAddress
		add esp, 4
		mov[pointer], eax
	}
	return std::string((char*)pointer);
}

uint32_t getFirstOpAddress() {
	void* proc = GetCurrentProcess();
	char lookFor[11] = { 0x49, 0x5F, 0x54, 0x45, 0x4C, 0x45, 0x50, 0x4F, 0x52, 0x54, 0x00 };
	char got[11] = {};
	for(uint32_t i = 0x400000; i < 0x7FFFFFFF; i++) {
		memcpy(&got, (void*)i, 11);
		if(memcmp(lookFor, got, 11) == 0) {
			return i;
		}
	}
	return 0;
}

uint32_t getProtocolVersion() {
	char lookFor[7] = { 0x53, 0x56, 0x57, 0x8D, 0x4D, 0xE8, 0xE8 };
	char got[7] = {};
	uint32_t version = 0;
	for(uint32_t i = 0x400000; i < 0x7FFFFFFF; i++) {
		memcpy(&got, (void*)i, 7);
		if(memcmp(lookFor, got, 7) == 0) {
			version = *(uint32_t*)(*(uint32_t*)(i + 0x10));
			break;
		}
	}
	return version;
}

void getNamingAddress() {
	void* proc = GetCurrentProcess();
	char lookFor[5] = { (char)0xB8, 0x00, 0x00, 0x00, 0x00 };
	uint32_t addr = getFirstOpAddress();
	memcpy(lookFor + 1, &addr, 4);
	char got[5] = {};
	for(uint32_t i = 0x400000; i < 0x7FFFFFFF; i++) {
		memcpy(&got, (void*)i, 5);
		if(memcmp(lookFor, got, 5) == 0) {
			namingAddress = i - 41;
			break;
		}
	}
}

unsigned long __stdcall getOpcodes(void* params) {
	getNamingAddress();
	uint32_t version = getProtocolVersion();
	if(namingAddress == 0) {
		MessageBoxA(0, "Could not naming address.", "Opcode DLL", 0);
		FreeLibraryAndExitThread(thisDll, 0);
	}

	std::ofstream f;
	f.open(version == 0 ? "opcodes.txt" : "protocol." + std::to_string(version) + ".map", std::ios::out);

	for(uint16_t i = 0; i < 0xFFFF; i++) {
		std::string name(GetOpCodeName(i));
		if(name.length() > 0) {
			f << name << " = " << i << "\n";
		}
	}

	f.close();
	MessageBoxA(0, "Opcodes found", "Opcode DLL", 0);
	FreeLibraryAndExitThread(thisDll, 0);
}

bool __stdcall DllMain(HMODULE dllModule, uint32_t dllReason, void* dllReserved) {
	if(dllReason == DLL_PROCESS_ATTACH) {
		thisDll = dllModule;
		CreateThread(0, 0, getOpcodes, 0, 0, 0);
	}

	return true;
}