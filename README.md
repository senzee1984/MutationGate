# MutationGate
MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.

It works by calling an unhooked NTAPI and replacing the unhooked NTAPI's SSN with hooked NTAPI's. In this way, the syscall is redirected to the hooked NTAPI's, and the inline hook can be bypassed without loading the 2nd ntdll module or modifying bytes within loaded ntdll's memory space. 

The provided project is only a `POC`, not a comprehensive implementation. For instance, you could use this approach to set hardware breakpoints for a set of functions. 

The function can also be WIN32API. In this way, the call stack looks more legitimate. For instance, set the 1st hbp at `DrawText+0` to redirect the execution to `NtDrawText+8`, and the 2nd hbp replaces the SSN saved in RAX. In this way, module `kernel32.dll` is not skipped.

## Description
EDR tends to set inline hooks for various NTAPI, especially those are usually leveraged in malware, such as `NtAllocVirtualMemory`, `NtOpenProcess`, etc. While other NTAPI that are not usually leveraged in malware tend not to have inline hook, such as `NtDrawText`. It is very unlikely that an EDR set inline hook for all NTAPI.   

Assume NTAPI `NtDrawText` is not hooked, while NTAPI `NtQueryInformationProcess` is hooked

Set a hardware breakpoint at NtDrawText+0x8, when the address is reached, modify RAX with NtQueryInformationProcess' Syscall Number. In this way, though the program reached NtDrawText address, SSN is changed, the syscall of NtQueryInformationProcess is transited.



## Example

![example](screenshot/poc.png)


## Disclaimer

## Advantages of MutationGate Approach



## Detection and Countermeasure of Detection

## Credits and References
