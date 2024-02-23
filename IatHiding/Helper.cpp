#include "Helper.h"


template<typename T>
constexpr BOOL ItsString()
{
	return std::is_same_v<T, const char*> || std::is_same_v<T, const wchar_t*>;
}

wchar_t* ConvertToWChar(const char* sData) {

	int nChars = MultiByteToWideChar(CP_ACP, 0, sData, -1, NULL, 0);

	wchar_t* wcstring = new wchar_t[nChars];

	MultiByteToWideChar(CP_ACP, 0, sData, -1, (LPWSTR)wcstring, nChars);

	return wcstring;

}

char* ConvertToChar(const wchar_t* sData) {

	size_t origsize = wcslen(sData) + 1;
	size_t convertedChars = 0;

	char* nstring = new char[origsize];
	wcstombs_s(&convertedChars, nstring, origsize, sData, _TRUNCATE);

	return nstring;
}

UINT32 WideStringToHash(wchar_t* wsData) {

	size_t sBufferSize = wcslen(wsData);
	wchar_t* pwcString = wsData;

	_wcslwr_s(pwcString, sBufferSize + 1);

	return Encryption::JenkinsOneAtATime32Bit(pwcString);
}

template<typename T>
FARPROC Helper::GetProcAddressR(HMODULE hModule, const T tFuncName) {

	if (!hModule) {
		printf("[!] HModule null addr exception.\n");
		return NULL;
	}

	PBYTE pBase = reinterpret_cast<PBYTE>(hModule);

	PIMAGE_DOS_HEADER pImgDosHdr = reinterpret_cast<PIMAGE_DOS_HEADER>(pBase);
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[!] Incorrect dos header...\n");
		return NULL;
	}

	PIMAGE_NT_HEADERS pImgNtHdrs = reinterpret_cast<PIMAGE_NT_HEADERS>(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
		printf("[!] Incorrect signature in NT...");
		return NULL;
	}

	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>
		(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD FunctionNameArray = reinterpret_cast<PDWORD>(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = reinterpret_cast<PDWORD>(pBase + pImgExportDir->AddressOfFunctions);
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
	PVOID pFuncttionAddress = nullptr;

	constexpr BOOL bItsString = ItsString<T>();

	UINT32 uiHashedModuleName = 0;
	const char* cModuleName = nullptr;

	if constexpr (std::is_same_v<T, const wchar_t*>) {
		const wchar_t* wcModuleName = reinterpret_cast<const wchar_t*>(tFuncName);
		cModuleName = ConvertToChar(wcModuleName);
	}
	else if constexpr (std::is_same_v<T, unsigned int> || std::is_same_v<T, int>)
		uiHashedModuleName = tFuncName;
	else
		cModuleName = reinterpret_cast<const char*>(tFuncName);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		PCHAR pFunctionName = reinterpret_cast<PCHAR>(pBase + FunctionNameArray[i]);
		WORD wFunctionOrdinal = FunctionOrdinalArray[i];

		if (!bItsString) {
			UINT32 uiHashedString = Encryption::JenkinsOneAtATime32Bit(pFunctionName);
			if (uiHashedString == uiHashedModuleName) {
				printf("[!] Found func name %s ADDRESS: 0x%p\n", pFunctionName ,reinterpret_cast<FARPROC>(pBase + FunctionAddressArray[wFunctionOrdinal]));
				return reinterpret_cast<FARPROC>(pBase + FunctionAddressArray[wFunctionOrdinal]);
			}
		}
		else {
			if (strstr(pFunctionName, cModuleName) != 0) {
				printf("[!] Function found %s ADDRESS: 0x%p\n", pFunctionName, pBase + FunctionAddressArray[wFunctionOrdinal]);
				return reinterpret_cast<FARPROC>(pBase + FunctionAddressArray[wFunctionOrdinal]);
			}
		}
	}
	if (bItsString) {
		delete[] cModuleName;
		cModuleName = nullptr;
	}
	return NULL;
}

template<typename T>
HMODULE Helper::GetModuleHandleR(const T tModuleName)
{
#ifdef _WIN64
	PPEB pProcEnvBlk = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
	PPEB pProcEnvBlk = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA pLdrData = reinterpret_cast<PPEB_LDR_DATA>(pProcEnvBlk->Ldr);
	if (!pLdrData) {
		printf("[!] LDR DATA in PEB is Null\n");
		return NULL;
	}

	PLDR_DATA_TABLE_ENTRY pDataTableEntry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(pLdrData->InMemoryOrderModuleList.Flink);
	if (!pDataTableEntry) {
		printf("[!] LDR DATA in PEB is Null\n");
		return NULL;
	}

	constexpr BOOL bItsString = ItsString<T>();
	
	UINT32 uiHashedModuleName = 0;
	const wchar_t* wcModuleName = nullptr;

	if constexpr (std::is_same_v<T, const char*>) {
		const char* cModuleName = reinterpret_cast<const char*>(tModuleName);
		wcModuleName = ConvertToWChar(cModuleName);
	}
	else if constexpr (std::is_same_v<T, unsigned int> || std::is_same_v<T, int>) 
		uiHashedModuleName = tModuleName;
	else 
		wcModuleName = reinterpret_cast<const wchar_t*>(tModuleName);
	
	while (pDataTableEntry) {

		if (pDataTableEntry->FullDllName.Length == NULL)
			break;

		if (!bItsString) {

			UINT32 uiHashedString = WideStringToHash(pDataTableEntry->FullDllName.Buffer);
			if (uiHashedString == uiHashedModuleName) {
				wprintf(L"[!] Found module name %s\n", pDataTableEntry->FullDllName.Buffer);
				return reinterpret_cast<HMODULE>(pDataTableEntry->InInitializationOrderLinks.Flink);
			}
		}
		else {
			if (_wcsicmp(pDataTableEntry->FullDllName.Buffer, wcModuleName) == 0) {
				wprintf(L"[!] Found module name %s\n", pDataTableEntry->FullDllName.Buffer);
				return reinterpret_cast<HMODULE>(pDataTableEntry->InInitializationOrderLinks.Flink);
			}
		}
		pDataTableEntry = *reinterpret_cast<PLDR_DATA_TABLE_ENTRY*>(pDataTableEntry);
	}

	if (bItsString) {
		delete[] wcModuleName;
		wcModuleName = nullptr;
	}

	return NULL;
}



UINT32 Encryption::JenkinsOneAtATime32Bit(const std::wstring& sName)
{
	UINT32 uResult = 0;

	SIZE_T Index = 0;
	SIZE_T Length = sName.size() - 1;

	while (Index != Length)
	{
		uResult += sName[Index++];
		uResult += uResult << JENKINS_INITIAL_SEED;
		uResult ^= uResult >> 6;
	}

	uResult += uResult << 3;
	uResult ^= uResult >> 11;
	uResult += uResult << 15;

	return uResult;
}

UINT32 Encryption::JenkinsOneAtATime32Bit(const std::string& sName)
{
	UINT32 uResult = 0;

	SIZE_T Index = 0;
	SIZE_T Length = sName.size() - 1;

	while (Index != Length)
	{
		uResult += sName[Index++];
		uResult += uResult << JENKINS_INITIAL_SEED;
		uResult ^= uResult >> 6;
	}

	uResult += uResult << 3;
	uResult ^= uResult >> 11;
	uResult += uResult << 15;

	return uResult;
}


