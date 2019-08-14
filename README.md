# RudiAC

A very rudimentary anti-cheat used for a circumstantial 2017 freelance project. Much of the behavior and functionality is circumstantial.
The project was to attach a client-sided anti-cheat to an old game private server which already had some third party proprietary security modules attached which leads to an anti-cheat with noticeable exceptions to odd behavior.

# Fundamentals

### Memory Integrity Check

Gathers a collection of memory pages initially within the game's module (anticheat::cheat_monitor::init) and generates a CRC32 hash based on the memory contents of each page (calc_vpt_hashes) - each validated every cycle (anticheat::cheat_monitor::check_pages).

### Protected Functions

Similar in concept to a memory integrity check, but specifically detects if Winsock routines designated as "protected" are hooked/modified, preventing user-mode packet modification and reading by software such as WPE Pro and rPE.

### Memory Honeypots

Memory honeypots are created within the init routine, where memory pages aren't yet accessed, but when they are (which they shouldn't be), it is detected. Prevents "cheat" scanners.

### Process Scanner

Scans each process based on the contents (process name, window name) and unique memory signature. I have outlined much of this rudimentary detection here: https://medium.com/@jasonmjohnson1/third-party-software-detection-f0ed396634cf

### Module Scanner

Scans the loaded modules in the process for any with suspicious names.

TBA: Signature scanning

### Anti-Debugging

Checks the PEB directly (instead of using IsDebuggerPresent, which can be easily looked up) for the value of the BeingDebugged flag as well as the value of NtGlobalFlag. Prone to just directly modifying the BeingDebugged flag to bypass this check though. DbgUiRemoteBreakIn is blocked because debug threads can't be executed in the process (DebugActiveProcess executes a thread within the process, but our process has memory bounds checking, simplified when thread scanning is mentioned.)

TBA: Arbitrary Vectored Exception Handling Detection

### Thread Blocking

Hooks RtlUserThreadStart and checks if the designated address of execution for the thread is within the correct memory bounds. In this case, it is called "image-only execution", where only threads within the primary image (and some other excluded images such as ucrtbased.dll) are allowed to have threads run. If a thread is running outside of these bounds then it is detected as malicious inside an invalid execution space. This also prevents debuggers from attaching the process since RtlUserThreadStart is executed before DbgUiRemoteBreakIn is called which executes outside of the secure boundaries.


