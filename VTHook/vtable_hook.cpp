// github.com/Imrglop/SignatureScanner

#include "vtable_hook.h"

#include <sstream>
#include <map>

std::map<LPVOID*, LPVOID*> detours;

int vh::hook(LPVOID* pfpTarget, LPVOID pDetour, LPVOID* pOriginal)
{
	if (pOriginal != NULL) {
		*pOriginal = *pfpTarget;
	}
	DWORD dwOldProtect;
	VirtualProtect(pfpTarget, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*pfpTarget = pDetour;
	detours[pfpTarget] = pOriginal;
	VirtualProtect(pfpTarget, sizeof(LPVOID), dwOldProtect, &dwOldProtect);
	return 0;
}

int vh::unhook(LPVOID* pfpTarget) {
	DWORD dwOldProtect;
	VirtualProtect(pfpTarget, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &dwOldProtect);
	*pfpTarget = *(detours[pfpTarget]);
	VirtualProtect(pfpTarget, sizeof(LPVOID), dwOldProtect, &dwOldProtect);
	return 0;
}

std::string vh::statusToString(int status) {
	switch (status) {
	case 0:
		return "Success.";
	case 1:
		return "Function is not detoured.";
	case 2:
		return "Function already hooked.";
	}
}