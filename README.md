# IatHiding

Example how to use 
```
printf("%p\n", Helper::GetProcAddressR(Helper::GetModuleHandleR(0x02CA3728), 0x497310D8));
printf("%p\n", Helper::GetProcAddressR(Helper::GetModuleHandleR("kernel32.dll"), "RtlMoveMemory"));
printf("%p\n", Helper::GetProcAddressR(Helper::GetModuleHandleR(L"kernel32.dll"), L"RtlMoveMemory"));
printf("%p\n", GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlMoveMemory"));
```

There is also a sample code how to hash strings
```
UINT32 hash = Encryption::JenkinsOneAtATime32Bit(L"RtlMoveMemory");
printf("hashed RtlMoveMemory %#010x\n", hash);

UINT32 hash = Encryption::JenkinsOneAtATime32Bit(L"kernel32.dll");
printf("hashed kernel %#010x\n", hash);
```
