#include <windows.h>
#include <iostream>

int main(void) {
	std::cout << ">> Awaiting TERA client..." << std::flush;
	
	char path[MAX_PATH];
	GetCurrentDirectoryA(MAX_PATH, path);
	std::string dllPath = std::string(path) + "\\fetch_opcodes.dll";

	HWND teraClient = FindWindowA("LaunchUnrealUWindowsClient", "TERA");
	while(!teraClient) {
		Sleep(100);
		teraClient = FindWindowA("LaunchUnrealUWindowsClient", "TERA");
	}

	unsigned long PID = 0;
	GetWindowThreadProcessId(teraClient, &PID);

	if(void* client = OpenProcess(PROCESS_ALL_ACCESS, false, PID)) {
		if(void* LoadLibA = (void*)GetProcAddress(GetModuleHandleA((char*)"kernel32.dll"), (char*)"LoadLibraryA")) {
			if(void* allocString = (void*)VirtualAllocEx(client, NULL, dllPath.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) {
				if(WriteProcessMemory(client, (void*)allocString, dllPath.c_str(), dllPath.length(), NULL)) {
					if(CreateRemoteThread(client, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibA, (void*)allocString, 0, NULL)) {
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