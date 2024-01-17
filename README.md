# MutationGate
MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.

It works by calling an unhooked NTAPI and replacing the unhooked NTAPI's SSN with hooked NTAPI's. In this way, the syscall is redirected to the hooked NTAPI's, and the inline hook can be bypassed without loading the 2nd ntdll module or modifying bytes within loaded ntdll's memory space. 

The provided project is only a `POC`, not a comprehensive implementation. For instance, you could use this approach to set hardware breakpoints for a set of functions. 

The function can also be WIN32API. For instance, we can set the 1st hbp at `DrawText+0` to redirect the execution to `NtDrawText+8`, and the 2nd hbp replaces the SSN saved in RAX. In this way, module `kernel32.dll` is not skipped, the call stack looks more legitimate. 

## Description
EDR tends to set inline hooks for various NTAPI, especially those are usually leveraged in malware, such as `NtAllocVirtualMemory`, `NtOpenProcess`, etc. While other NTAPI that are not usually leveraged in malware tend not to have inline hook, such as `NtDrawText`. It is very unlikely that an EDR set inline hook for all NTAPI.   

Assume NTAPI `NtDrawText` is not hooked, while NTAPI `NtQueryInformationProcess` is hooked, the steps are as follows:

1. Get the address of `NtDrawText`. It can be achieved by utilizing `GetModuleHandle` and `GetProcAddress` combination, or a custom implementation of them via PEB walking.
2. Prepare arguments for `NtQueryInformationProcess`
3. Set a hardware breakpoint at `NtDrawText+0x8`, when the execution reaches this address, SSN of `NtDrawText` is saved in RAX, but syscall is not called yet.
4. Retrieve the SSN of `NtQueryInformationProcess`. Inside the exception handler, update RAX with NtQueryInformationProcess' SSN. I.e., the original SSN was replaced.
5. Since we called `NtDrawText` but with `NtQueryInformationProcess`' arguments, the call should be failed. However, since we changed the SSN, the syscall is successful. 



## Example

![example](screenshot/poc.png)


## Disclaimer
1. MutationGate is not an extension or variant of various Gate. Because those Gate focus more on retrieving SSN of NTAPI, MutationGate focuses on bypassing the inline hook in NTAPI.
2. MutationGate is able to bypass inline hook in NTAPI, however, the individual technique does not guarantee to bypass EDR, because EDR has multiple detection dimensions, inline hook is one of them.
3. The project is a POC, not a complete and comprehensive implementation.



## Advantages of MutationGate Approach



## Detection and Countermeasure of Detection

## Credits and References
