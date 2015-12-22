#include <winsock2.h>
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
void Start();

DWORD dwKakao = 0;

DWORD Kakao_return_1 = 0;
BYTE jmp[6] = { 0xe9,0x00,0x00,0x00,0x00,0xc3 };

char *format1 = "1 - > %s\n";
bool bCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask) return 0;
	return (*szMask) == NULL;
}
DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask)
{
	for (DWORD i = 0; i<dwLen; i++)
		if (bCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (DWORD)(dwAddress + i);
	return 0;
}
BOOL MemoryEdit(VOID *lpMem, VOID *lpSrc, DWORD len)
{
	DWORD lpflOldProtect, flNewProtect = PAGE_READWRITE;
	unsigned char * pDst = (unsigned char *)lpMem,
		*pSrc = (unsigned char *)lpSrc;
	if (VirtualProtect(lpMem, len, flNewProtect, &lpflOldProtect))
	{
		while (len-- > 0) *pDst++ = *pSrc++;
		return(0);
	}
	return(1);
}
DWORD Hook(LPVOID lpFunction)
{
	DWORD dwAddr = Kakao_return_1 - 8;
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);

	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
	return dwAddr;
}
DWORD HookFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandleA(lpModule), lpFuncName);
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0);
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
	return dwAddr;
}
BOOL UnHookFunction(LPCSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandleA(lpModule), lpFuncName);
	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0))
		return TRUE;
	return FALSE;
}
void __declspec(naked) Kakao_hook_1()
{
	__asm
	{
		mov eax, dword ptr ss : [ESP + 0x20]
		mov esi, DWORD ptr ss : [ESP + 0x24]
			pushad
			push eax
			push format1
			call printf
			add esp, 8
			popad
			jmp[Kakao_return_1]
	}
}
void Start()
{
	DWORD dwSize = 0x180000;
	DWORD dwAddress = 0;
	do
	{
		dwKakao = (DWORD)GetModuleHandleA("KakaoTalk.exe");
		Sleep(10);
	} while (!dwKakao);
	Sleep(100);
	printf("Kakao: %x\n", dwKakao);

	dwAddress = FindPattern(dwKakao, dwSize, (PBYTE)"\xe8\x00\x00\x00\x00\x8b\x44\x24\x20\x8b\x74\x24\x24", "x????xxxxxxxx");
	printf("Address: %x\n", dwAddress);
	Kakao_return_1 = dwAddress + 13;
	Hook(Kakao_hook_1);
}
BOOL APIENTRY DllMain(HMODULE hModul, DWORD ul_reason_for_ca, LPVOID lpReserve)
{
	switch (ul_reason_for_ca)
	{
	case DLL_PROCESS_ATTACH:
		AllocConsole();
		freopen("CON", "w", stdout);
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)Start, NULL, NULL, NULL);

	case DLL_THREAD_ATTACH:

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
