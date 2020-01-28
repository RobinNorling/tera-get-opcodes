#include <Windows.h>
#include <Psapi.h>
#include <string>
#include <fstream>

uint32_t baseAddress = 0;
uint32_t maxAddress = 0;
HMODULE thisDll;

uint32_t getFirstOpAddress() {
	uint8_t lookFor[11] = { 0x49, 0x5F, 0x54, 0x45, 0x4C, 0x45, 0x50, 0x4F, 0x52, 0x54, 0x00 };
	for(uint32_t i = baseAddress; i < maxAddress; i++) {
		if(memcmp(lookFor, (void*)i, 11) == 0) {
			return i;
		}
	}
	return 0;
}

uint32_t getProtocolVersion() {
	uint8_t lookFor[13] = { 0x55, 0x02, 0x04, 0x00, 0x00, 0x00, 0x3C, 0xAB, 0x56, 0x02, 0x68, 0xAC, 0x56 };
	for(uint32_t i = baseAddress; i < maxAddress; i++) {
		if(memcmp(lookFor, (void*)i, 13) == 0) {
			return *(uint32_t*)(i + 0x22);
		}
	}
	return 0;
}

uint32_t getNamingAddress() {
	uint8_t lookFor[5] = { 0xB8, 0x00, 0x00, 0x00, 0x00 };
	uint32_t addr = getFirstOpAddress();
	memcpy(lookFor + 1, &addr, 4);
	for(uint32_t i = baseAddress; i < maxAddress; i++) {
		if(memcmp(lookFor, (void*)i, 5) == 0) {
			return i - 41;
		}
	}
	return 0;
}

unsigned long __stdcall getOpcodes(void*) {
	uint16_t invalidTries = 0;
	uint32_t version = 0;
	while(!(version = getProtocolVersion())) {
		if(++invalidTries > 10) {
			break;
		}
		Sleep(500);
	}

	uint32_t namingAddress = getNamingAddress();
	if(namingAddress == 0) {
		MessageBoxA(0, "Could not find naming address.", "Opcode DLL", 0);
		FreeLibraryAndExitThread(thisDll, 0);
	}

	std::ofstream f("protocol." + std::to_string(version) + ".map", std::ios::out);
	bool first = true;

	for(uint32_t i = 0; i <= 0xFFFF; i++) {
		std::string name(((char*(*)(uint32_t))(namingAddress))(i));
		if(name.length() > 1 && name[1] == '_' && (name[0] == 'C' || name[0] == 'S' || name[0] == 'I')) {
			if(!first) { f << "\n"; } else { first = false; }
			f << name << " = " << i;
		}
	}

	f.close();
	MessageBoxA(0, "Opcodes found", "Opcode DLL", 0);
	FreeLibraryAndExitThread(thisDll, 0);
}

bool __stdcall DllMain(HMODULE dllModule, uint32_t dllReason, void*) {
	if(dllReason == DLL_PROCESS_ATTACH) {
		MODULEINFO clientInfo;
		if(GetModuleInformation(GetCurrentProcess(), GetModuleHandleA("TERA.exe"), &clientInfo, sizeof(clientInfo)) && clientInfo.SizeOfImage > 0) {
			baseAddress = reinterpret_cast<uint32_t>(clientInfo.lpBaseOfDll);
			maxAddress = baseAddress + 0x2A00000;
			thisDll = dllModule;
			CreateThread(0, 0, getOpcodes, 0, 0, 0);
		}
	}

	return true;
}
