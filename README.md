# MutationGate
MutationGate is a new approach to bypass EDR's inline hooking by utilizing hardware breakpoint to redirect the syscall.

It works by calling an unhooked NTAPI and replacing the unhooked NTAPI's SSN with hooked NTAPI's. In this way, the syscall is redirected to the hooked NTAPI's, and the inline hook can be bypassed without loading the 2nd ntdll module or modifying bytes within loaded ntdll's memory space. 


## Description
Assume NTAPI `NtDrawText` is not hooked, while NTAPI `NtQueryInformationProcess` is hooked

Set a hardware breakpoint at NtDrawText+0x8, when the address is reached, modify RAX with NtQueryInformationProcess' Syscall Number. In this way, though the program reached NtDrawText address, SSN is changed, the syscall of NtQueryInformationProcess is transited.



## Example

![example](screenshot/poc.png)


## Disclaimer

## Advantages of MutationGate Approach



## Detection and Countermeasure of Detection

## Credits and References
