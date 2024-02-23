#pragma once

#include <Windows.h>
#include <cstdio>
#include <string>
#include <type_traits>
#include <typeinfo>
#include "PEStructs.h"

namespace Helper {


	template<typename T>
	FARPROC GetProcAddressR(HMODULE hModule, const T tFuncName );
	
	template<typename T>
	HMODULE GetModuleHandleR(const T tModuleName);


	template HMODULE GetModuleHandleR(int tModuleName);
	template HMODULE GetModuleHandleR(unsigned int tModuleName);
	template HMODULE GetModuleHandleR(const char* tModuleName);
	template HMODULE GetModuleHandleR(const wchar_t* tModuleName);

	template FARPROC GetProcAddressR(HMODULE hModule, int tFuncName);
	template FARPROC GetProcAddressR(HMODULE hModule, unsigned int tFuncName);
	template FARPROC GetProcAddressR(HMODULE hModule, const char* tFuncName);
	template FARPROC GetProcAddressR(HMODULE hModule, const wchar_t* tFuncName);


};

namespace Encryption {

#define JENKINS_INITIAL_SEED    10
	UINT32 JenkinsOneAtATime32Bit(const std::wstring& sName);
	UINT32 JenkinsOneAtATime32Bit(const std::string& sName);

}
