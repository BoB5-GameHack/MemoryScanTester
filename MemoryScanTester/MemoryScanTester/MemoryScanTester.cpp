#include <stdio.h>
#include <io.h>

#include <Windows.h>
#include <TlHelp32.h>

#include <vector>
#include <string>

DWORD GetPidByProcessName(WCHAR *name) {
	PROCESSENTRY32W entry;
	memset(&entry, 0, sizeof(PROCESSENTRY32W));
	entry.dwSize = sizeof(PROCESSENTRY32W);

	DWORD pid = -1;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (Process32FirstW(hSnapShot, &entry)) {
		do {
			if (!wcscmp(name, entry.szExeFile)) {
				pid = entry.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapShot, &entry));
	}

	CloseHandle(hSnapShot);

	return pid;
}

int MemoryScanEx(HANDLE hProcess, BYTE *pattern, SIZE_T length, std::vector<LPVOID>& list) {
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);

	LPVOID lpStartAddress = (LPVOID)sysinfo.lpMinimumApplicationAddress;
	LPVOID lpEndAddress = (LPVOID)sysinfo.lpMaximumApplicationAddress;

	std::string strPattern(pattern, pattern + length);

	while (lpStartAddress < lpEndAddress) {
		MEMORY_BASIC_INFORMATION mbi = { 0, };
		if (!VirtualQueryEx(hProcess, lpStartAddress, &mbi, sizeof(mbi))) {
			return -1;
		}

		if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_GUARD) && mbi.Protect != PAGE_NOACCESS) {
			if ((mbi.Protect & PAGE_EXECUTE_READ) || (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
				BYTE *dump = new BYTE[mbi.RegionSize];
				ReadProcessMemory(hProcess, lpStartAddress, dump, mbi.RegionSize, NULL);
				std::string mem(dump, dump + mbi.RegionSize);

				size_t n = -1;
				while (true) {
					n = mem.find(strPattern, n + 1);
					if (n == std::string::npos) {
						break;
					}

					list.push_back((LPVOID)((SIZE_T)lpStartAddress + n));
				}

				delete[] dump;
			}
		}

		lpStartAddress = (LPVOID)((SIZE_T)lpStartAddress + mbi.RegionSize);
	}

	return 1;
}

#define PROC_NAME L"S1GameProtected.exe"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		printf("[*] USAGE : MemoryScanTester FILENAME\n");
		return 1;
	}

	if (access(argv[1], 0)) {
		printf("[*] invalid filename\n");
		return 1;
	}

	FILE *fp = fopen(argv[1], "r");

	int length;
	fscanf(fp, "%d", &length);

	BYTE *pattern = new BYTE[length];

	for (int i = 0; i < length; ++i) {
		fscanf(fp, "%02x", &pattern[i]);
	}
	fclose(fp);

	DWORD pid = GetPidByProcessName(PROC_NAME);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	std::vector<LPVOID> list;
	MemoryScanEx(hProcess, pattern, length, list);

	for (auto iter = list.begin(); iter != list.end(); ++iter) {
		printf("%p\n", *iter);
	}

	delete[] pattern;
}