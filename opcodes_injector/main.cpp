#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

unsigned long findProcessId(const std::wstring& processName) {
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processesSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}

	Process32First(processesSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile)) {
		CloseHandle(processesSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processesSnapshot, &processInfo)) {
		if (!processName.compare(processInfo.szExeFile)) {
			CloseHandle(processesSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processesSnapshot);
	return 0;
}

int main(void) {
	std::cout << ">> Awaiting TERA client..." << std::flush;

	char path[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, path);
	std::string dllPath = std::string(path) + "\\fetch_opcodes.dll";

	unsigned long PID = 0;
	while(!PID) {
		Sleep(100);
		PID = findProcessId(std::wstring(L"TERA.exe"));
	}

	if (void* client = OpenProcess(PROCESS_ALL_ACCESS, false, PID)) {
		if (void* LoadLibA = (void*)GetProcAddress(GetModuleHandleA((char*)"kernel32.dll"), (char*)"LoadLibraryA")) {
			if (void* allocString = (void*)VirtualAllocEx(client, NULL, dllPath.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) {
				if (WriteProcessMemory(client, (void*)allocString, dllPath.c_str(), dllPath.length(), NULL)) {
					if (CreateRemoteThread(client, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibA, (void*)allocString, 0, NULL)) {
						std::cout << " Injected: " << PID << std::endl;
						Sleep(1000);
						return 0;
					}
				}
			}
		}
		CloseHandle(client);
	}

	std::cout << " Failed to inject! Try running as administrator." << std::endl;
	getchar();
	return 0;
}