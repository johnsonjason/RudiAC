#include "stdafx.h"
#include "cheat-monitor.h"

static anticheat::reg_thread_cb_data callback_information = { 0 };

//
// Get pointer to Winsock module
// Load pointers of Winsock routines into the protected array
//

static HMODULE winsock = GetModuleHandleA("ws2_32.dll");
static std::array<void*, 8> protected_winsock_functions =
{
	GetProcAddress(winsock, "send"), GetProcAddress(winsock, "recv"),
	GetProcAddress(winsock, "sendto"), GetProcAddress(winsock, "recvfrom"),
	GetProcAddress(winsock, "WSASend"), GetProcAddress(winsock, "WSARecv"),
	GetProcAddress(winsock, "WSASendTo"), GetProcAddress(winsock, "WSARecvFrom")
};

//
// Process black list
// List for the process scanner
//

static std::vector<std::wstring> process_scan =
{
	L"artmoney",
	L"aimbot",
	L"trainer",
	L"cheatengine",
	L"Cheat",
	L"cheat",
	L"cheat engine",
	L"inject",
	L"debugger",
	L"windbg",
	L"x64dbg",
	L"x32dbg",
	L"ollydbg",
	L"debug",
	L"hack",
	L"memory viewer",
	L"injector",
	L"wpepro"
};

//
// Module blacklist
// List of malicious module names to detect
//

static std::vector<std::wstring> module_scan = {
	L"artmoney",
	L"aimbot",
	L"trainer",
	L"wpespy",
	L"windbg",
	L"cheat",
	L"asmjit",
	L"titanengine",
	L"x32_dbg",
	L"x64_dbg"
	L"x64dbg",
	L"x32dbg",
	L"luaclient",
	L"lua53"
	L"libipt",
	L"winhook",
	L"ollydbg",
	L"speedhack",
	L"vehdebug",
	L"allochook",
	L"ced3d",
	L"wpespy",
	L"timbus"
};

/* Excepted page list
* List of pages to be exempt from the memory integrity check
*/
static std::vector<void*> pg_exceptions =
{
	reinterpret_cast<void*>(0x00ABB000),
	reinterpret_cast<void*>(0x008E9000)
};

//
// Excepted page range list
// List of page/address ranges to be exempt from the memory integrity check
//

static std::vector<std::pair<std::size_t, std::size_t>> pg_range_exceptions = 
{
	{0x00800000, 0x008FFFFF},
	{0x00900000, 0x009FFFFF},
	{0x00A00000, 0x00AFFFFF}
};

static std::vector<void*> honey_pots;

std::vector<std::pair<std::size_t, std::size_t>> anticheat::thread_monitor::lh_addr_pairs;
std::vector<std::pair<std::size_t, std::vector<std::uint8_t>>> anticheat::cheat_analyzer::signature_pairs;


//
// Signature of RtlUserThreadStart
//

static const std::array<std::uint8_t, 8> tcallback_sig =
{
	0x89, 0x44, 0x24, 0x04,
	0x89, 0x5C, 0x24, 0x08
};

//
// Safely close a handle without throwing any type of debug event/exception
//

inline void anticheat::close_valid_handle(HANDLE reference)
{
	if (reference != INVALID_HANDLE_VALUE && reference != nullptr)
	{
		CloseHandle(reference);
	}
}

/*++

Routine Description:

	Exits the anti-cheat and executing process
	Exits due to an error found by the anti-cheat

Parameters:

	reason - Reason for termination

Return Value:

	None

--*/

__declspec(noinline) void anticheat::hard_exit(anticheat::exit_code reason)
{
	HANDLE logfile = CreateFileA("cerror.txt", GENERIC_WRITE, FILE_SHARE_READ,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	std::size_t bytes_written;

	//
	// Determine the reason the anti-cheat is exiting
	//

	switch (reason)
	{
		//
		// A generic error was detected by the anti-cheat 
		//

		case anticheat::exit_code::generic:
			WriteFile(logfile, "Error detected 0x00000001", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;

		//
		// A malicious process was detected by the anti-cheat
		//

		case anticheat::exit_code::process_detected:
			WriteFile(logfile, "Error detected 0x00000002", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;
		
		//
		// A malicious module/DLL loaded in the process has been detected by the anti-cheat
		//

		case anticheat::exit_code::module_detected:
			WriteFile(logfile, "Error detected 0x00000003", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;
		
		//
		// A memory integrity check failed to validate the checksum for a page - modification detected 
		//

		case anticheat::exit_code::memory_detected:
			WriteFile(logfile, "Error detected 0x00000004", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;
		
		//
		// A debugger was detected by the anti-cheat 
		//

		case anticheat::exit_code::debug_detected:
			WriteFile(logfile, "Error detected 0x00000005", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;
		
		//
		// (Experimental) A remote/malicious thread injected into the process has been detected by the anti-cheat 
		//

		case anticheat::exit_code::thread_detection:
			WriteFile(logfile, "Error detected 0x00000006", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;

		//
		// A hook to a specific function such as WSASend was detected
		//

		case anticheat::exit_code::hook_detected:
			WriteFile(logfile, "Error detected 0x00000007", 33, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;

		//
		// Generic error occurred
		//

		default:
			WriteFile(logfile, "Error occurred", 22, reinterpret_cast<unsigned long*>(&bytes_written), nullptr);
			break;
	}

	close_valid_handle(logfile);

	STARTUPINFOA startup_info = { 0 };
	PROCESS_INFORMATION process_info = { 0 };

	//
	// Open the game launcher with the displayed error and then terminate the current process
	//

	CreateProcessA("Game.exe", NULL, NULL, NULL, NULL, NULL, NULL, NULL, &startup_info, &process_info);
	CloseHandle(process_info.hProcess);
	CloseHandle(process_info.hThread);
	TerminateProcess(GetCurrentProcess(), static_cast<std::uint32_t>(reason));
}

/*++

Routine Description:

	Schedules the current thread to sleep for a specified amount of time
	Useful for CPU-intensive scanning functions

Parameters:

	time - Time to sleep

Return Value:

	None

--*/

void anticheat::sleep_time(std::size_t time)
{
	//
	// Sleep for arg time
	//

	Sleep(time); 
}

/*++

Routine Description:

	Get the module information for the specified module passed in the constructor arguments (mod)
	Initialize the monitor's members with the module information

Parameters:

	mod - Name of the module

Return Value:

	None

--*/

anticheat::cheat_monitor::cheat_monitor(LPCSTR mod)
{
	MODULEINFO temp_info;

	//
	// Get the size and base address of the module 
	//

	if (!K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(mod), &temp_info, sizeof(temp_info)))
	{
		throw static_cast<std::uint32_t>(anticheat::mod_info_failure);
	}

	//
	// Get the name of the module - useful for nullptr 
	//

	if (!K32GetModuleBaseNameA(GetCurrentProcess(), GetModuleHandleA(mod), this->module_name, sizeof(anticheat::image_name)))
	{
		throw static_cast<std::uint32_t>(anticheat::mod_name_failure);
	}

	this->module_size = temp_info.SizeOfImage;
	this->module_base = temp_info.lpBaseOfDll;
}

/*++

Routine Description:

	Initializes the cheat monitor and checks if any nonce's were already executed
	Enumerates each page in the local module for the monitor based on certain attributes
	Initializes synchronization objects
	Calculates the hashes for the pages

Parameters:

	None

Return Value:

	None

--*/

anticheat::nonce anticheat::cheat_monitor::init()
{
	//
	// Check if init nonce already executed
	//

	if (this->nonce_container[anticheat::nonce_code::init] == anticheat::nonce_code::init)
	{
		throw static_cast<std::uint32_t>(anticheat::nonce_exception::ran);
	}

	this->flag_nonce(anticheat::nonce_code::init);
	MEMORY_BASIC_INFORMATION mbi;

	//
	// Enumerate each page in the module for specific attributes and store their VAs in a list 
	//

	for (std::size_t page_count = reinterpret_cast<std::size_t>(this->module_base); page_count < (reinterpret_cast<std::size_t>(this->module_base) + this->module_size); page_count++)
	{
		anticheat::page_unit temporary;

		//
		// Query the attributes of a page 
		//

		VirtualQuery(reinterpret_cast<void*>(page_count), &mbi, sizeof(mbi));
		temporary.access = static_cast<anticheat::accessibility>(mbi.Protect);
		
		//
		// Only index certain pages based on their protection 
		//

		if (temporary.access == anticheat::accessibility::execute ||
			temporary.access == anticheat::accessibility::read_execute ||
			temporary.access == anticheat::accessibility::read_write_execute ||
			temporary.access == anticheat::accessibility::execute_wcopy)
		{
			temporary.page_address = mbi.BaseAddress;
			temporary.size = mbi.RegionSize;
			this->module_pages.push_back(temporary);
		}
		page_count += mbi.RegionSize;
	}

	//
	// Setup memory honeypots 
	//

	honey_pots.push_back(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
	honey_pots.push_back(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READONLY));
	honey_pots.push_back(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	honey_pots.push_back(VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READ));

	//
	// Initialize synchronization objects for the scanners and put the scanner in a ready state 
	//

	InitializeCriticalSection(&this->scan_section);
	InitializeConditionVariable(&this->scan_condition);
	this->scan_stop = anticheat::scan_state::ready;

	//
	// Calculate the hashes for each page 
	//

	this->calc_vpt_hashes();
}

/*++

Routine Description:

	Calculates the hashes for the enumerated list of each virtual page - calculates only once 

Parameters:

	None

Return Value:

	None

--*/

anticheat::nonce anticheat::cheat_monitor::calc_vpt_hashes()
{
	//
	// Check if a page hash calculation has already been done
	//

	if (this->nonce_container[anticheat::nonce_code::hash] == anticheat::nonce_code::hash)
	{
		throw static_cast<std::uint32_t>(anticheat::nonce_exception::ran);
	}

	this->flag_nonce(anticheat::nonce_code::hash);

	//
	// Iterate over each page and generate a CRC32 hash for them
	//

	for (std::size_t vpt_i = 0; vpt_i < static_cast<std::size_t>(this->module_pages.size()); vpt_i++)
	{
		this->module_pages[vpt_i].page_checksum = anticheat::error_checking::crc_crypt(this->module_pages[vpt_i].page_address, this->module_pages[vpt_i].size);
	}
}


/*++

Routine Description:

	Set the nonces to initialized if they executed so they do not execute more than once

Parameters:

	code - Which nonce has been executed

Return Value:

	None

--*/

void anticheat::cheat_monitor::flag_nonce(anticheat::nonce_code code)
{
	switch (code)
	{
	case anticheat::nonce_code::init:
		this->nonce_container[anticheat::nonce_code::init] = anticheat::nonce_code::init;
		return;
	case anticheat::nonce_code::hash:
		this->nonce_container[anticheat::nonce_code::hash] = anticheat::nonce_code::hash;
		return;
	case anticheat::nonce_code::scan:
		this->nonce_container[anticheat::nonce_code::scan] = anticheat::nonce_code::scan;
		return;
	}
}

static inline bool except_page(void* page)
{
	for (const std::pair<std::size_t, std::size_t>& range : pg_range_exceptions)
	{
		if (reinterpret_cast<std::size_t>(page) > range.first && reinterpret_cast<std::size_t>(page) < range.second)
		{
			return true;
		}
	}
	return false;
}

/*++
Routine Description:

Rudimentary anti-debug checks for a circumstantial anti-cheat

Parameters:

None

Return Value:

Boolean - Indicates whether a debugger is present (true) or not present (false)

--*/

static inline bool check_debugger()
{
	//
	// Explicitly read from the Process Environment Block rather than calling IsDebuggerPresent
	// IsDebuggerPresent can be easily symbolically looked up and patched
	// However, this is prone to another shared issue - manually writing that a debugger is not present to the PEBs memory section
	//

	std::uint8_t* p_env_block = reinterpret_cast<std::uint8_t*>((__readfsdword(0x30)) + anticheat::dbgp_env::being_debugged);
	if (*p_env_block == static_cast<std::uint8_t>(true))
	{
		return true;
	}
	else if (*(p_env_block + anticheat::dbgp_env::nt_globalflag) == 0x70)
	{
		return true;
	}
	return false;
}


/*++

Routine Description:

	Checks protected Winsock routine (within the protected_winsock_functions array) headers for if they are patched/hooked

Parameters:

	None

Return Value:

	Boolean - Indicates whether a protected routine has been modified (true) or if it has not been modified (false)

--*/

static inline bool check_wsock_hooks()
{
	if (winsock == nullptr)
	{
		return false;
	}
	for (std::size_t wfunc = 0; wfunc < protected_winsock_functions.size(); wfunc++)
	{
		if (*reinterpret_cast<std::uint8_t*>(protected_winsock_functions[wfunc]) == anticheat::jmphook_instr ||
			*reinterpret_cast<std::uint8_t*>(protected_winsock_functions[wfunc]) == anticheat::callhook_instr)
		{
			return true;
		}
	}
	return false;
}


/*++

Routine Description:

	Checks the initial memory honeypots if they have been triggered

Parameters:

	None

Return Value:

	Boolean - Indicates whether any of the memory honeypots have been accessed (true) or if they have not been accessed (false)

--*/

static inline bool check_mem_honeypots()
{
	for (void* pot : honey_pots)
	{
		PSAPI_WORKING_SET_EX_INFORMATION info = { 0 };
		info.VirtualAddress = pot;
		if (K32QueryWorkingSetEx(GetCurrentProcess(), &info, sizeof(PSAPI_WORKING_SET_EX_INFORMATION)))
		{
			if (info.VirtualAttributes.Valid == true)
			{
				return true;
			}
		}
	}
	return false;
}


/*++

Routine Description:

	Checks the integrity of the memory pages part of the error checking algorithm
	Runs secondary, tertiary, and quaternary checks for other behavior

Parameters:

	A "vector" or list of pages to be used for validation and integrity checking

Return Value:

	None

--*/

void anticheat::cheat_monitor::check_pages(const std::vector<anticheat::page_unit>& pages)
{
	for (std::size_t page = 0; page < pages.size(); page++)
	{
		if (pages[page].page_checksum != anticheat::error_checking::crc_crypt(pages[page].page_address, pages[page].size))
		{
			if (!except_page(pages[page].page_address))
			{
				anticheat::hard_exit(anticheat::exit_code::memory_detected);
			}
		}
	}
	if (check_mem_honeypots())
	{
		anticheat::hard_exit(anticheat::exit_code::memory_detected);
	}
	if (check_debugger())
	{
		anticheat::hard_exit(anticheat::exit_code::debug_detected);
	}
	if (check_wsock_hooks())
	{
		anticheat::hard_exit(anticheat::exit_code::hook_detected);
	}
}


/*++
Routine Description:

	Schedules (or does not schedule, but runs constant) the integrity check

Parameters:

	pthis - Acts as a "this" pointer for an object, for a procedurally designed routine

Return Value:

	ulnonce - Returns a status code for a "nonce" routine that only executes once

--*/

anticheat::ulnonce __stdcall anticheat::cheat_monitor::global_scan_schedule(void* pthis)
{
	anticheat::cheat_monitor* __this = reinterpret_cast<anticheat::cheat_monitor*>(pthis);
	if (__this->scan_cycles)
	{
		for (std::size_t ci = 0; ci < __this->scan_cycles; ci++)
		{
			__this->check_pages(__this->module_pages);
			anticheat::sleep_time(__this->time_between_scans);
		}
	}
	else
	{
		while (true)
		{
			__this->check_pages(__this->module_pages);
			anticheat::sleep_time(__this->time_between_scans);
		}
	}
	return 0;
}


/*++
Routine Description:

	Secondary controller for the scheduling of the memory integrity checker

Parameters:

	pthis - Acts as a "this" pointer for an object, for a procedurally designed routine

Return Value:

	ulnonce - Returns a status code for a "nonce" routine that only executes once

--*/

anticheat::ulnonce __stdcall anticheat::cheat_monitor::global_start_scan(void* pthis)
{
	anticheat::cheat_monitor* __this = reinterpret_cast<anticheat::cheat_monitor*>(pthis);
	if (__this->nonce_container[anticheat::nonce_code::scan] == anticheat::nonce_code::scan)
	{
		throw static_cast<std::uint32_t>(anticheat::nonce_exception::ran);
	}

	__this->flag_nonce(anticheat::nonce_code::scan);
	__this->scan_stop = anticheat::scan_state::run;

	while (true)
	{
		if (__this->scan_stop == anticheat::scan_state::suspend)
		{
			EnterCriticalSection(&__this->scan_section);
			SleepConditionVariableCS(&__this->scan_condition, &__this->scan_section, INFINITE);
			__this->scan_stop = anticheat::scan_state::run;
			LeaveCriticalSection(&__this->scan_section);
		}
		else if (__this->scan_stop == anticheat::scan_state::wait)
		{
			anticheat::sleep_time(__this->stop_time);
			__this->scan_stop = anticheat::scan_state::run;
		}
		__this->check_pages(__this->module_pages);
	}

	return 0;
}

anticheat::ulnonce __stdcall anticheat::thread_monitor::scan_processes(void* pthis)
{
	anticheat::thread_monitor* __this = reinterpret_cast<anticheat::thread_monitor*>(pthis);
	HANDLE processes_snapshot = nullptr;
	PROCESSENTRY32W process_info = { 0 };
	process_info.dwSize = sizeof(PROCESSENTRY32W);

	while (true)
	{
		close_valid_handle(processes_snapshot);

		processes_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

		if (processes_snapshot == INVALID_HANDLE_VALUE)
		{
			goto invalid_execution;
		}

		Process32FirstW(processes_snapshot, &process_info);
		do
		{
			Sleep(__this->process_scan_time);
			std::wstring process_string(process_info.szExeFile);
			std::transform(process_string.begin(), process_string.end(), process_string.begin(), ::tolower);
			for (const std::wstring& scan : process_scan)
			{
				if (process_string.find(scan) != std::wstring::npos)
				{
					close_valid_handle(processes_snapshot);
					anticheat::hard_exit(anticheat::exit_code::process_detected);
					return 0;
				}
			}
			if (FindWindowA(nullptr, "Cheat Engine"))
			{
				close_valid_handle(processes_snapshot);
				anticheat::hard_exit(anticheat::exit_code::process_detected);
				return 0;
			}
			anticheat::cheat_analyzer::scan_signature(process_info.th32ProcessID);
		} while (Process32NextW(processes_snapshot, &process_info));
	}

invalid_execution:
	close_valid_handle(processes_snapshot);
	anticheat::hard_exit(anticheat::exit_code::generic);
	return 0;
}

anticheat::ulnonce __stdcall anticheat::cheat_monitor::scan_modules(void* pthis)
{
	anticheat::cheat_monitor* __this = reinterpret_cast<anticheat::cheat_monitor*>(pthis);
	HANDLE modules_snapshot = nullptr;
	MODULEENTRY32W module_info = { 0 };
	module_info.dwSize = sizeof(MODULEENTRY32W);

	while (true)
	{
		close_valid_handle(modules_snapshot);
		modules_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());

		if (modules_snapshot == INVALID_HANDLE_VALUE)
		{
			goto invalid_execution;
		}

		Module32FirstW(modules_snapshot, &module_info);
		do
		{
			Sleep(__this->proc_mod_time);
			std::wstring module_string(module_info.szModule);
			std::transform(module_string.begin(), module_string.end(), module_string.begin(), ::tolower);

			for (const std::wstring& scan : module_scan)
			{
				if (module_string.find(scan) == 0)
				{
					close_valid_handle(modules_snapshot);
					anticheat::hard_exit(anticheat::exit_code::module_detected);
					return 0;
				}
			}
		} while (Module32NextW(modules_snapshot, &module_info));
	}

invalid_execution:
	close_valid_handle(modules_snapshot);
	anticheat::hard_exit(anticheat::exit_code::generic);
	return 0;
}

void anticheat::cheat_monitor::global_restart_scan()
{
	WakeConditionVariable(&this->scan_condition);
}

void anticheat::cheat_monitor::global_stop_scan(std::size_t time)
{
	if (time == 0)
	{
		this->scan_stop = anticheat::scan_state::suspend;
		return;
	}
	this->stop_time = time;
	this->scan_stop = anticheat::scan_state::wait;
}

HANDLE anticheat::cheat_monitor::schedule(PTHREAD_START_ROUTINE routine)
{
	return CreateThread(nullptr, 0, routine, this, 0, nullptr);
}

HANDLE anticheat::thread_monitor::schedule(PTHREAD_START_ROUTINE routine)
{
	return CreateThread(nullptr, 0, routine, this, 0, nullptr);
}



static bool check_pairs(std::size_t exec)
{
	for (std::size_t i = 0; i < anticheat::thread_monitor::lh_addr_pairs.size(); i++)
	{
		if (exec >= anticheat::thread_monitor::lh_addr_pairs[i].first &&
			exec <= anticheat::thread_monitor::lh_addr_pairs[i].second)
		{
			return true;
		}
	}
	return false;
}

static __declspec(naked) void h_ntthread_init_callback(PTHREAD_START_ROUTINE exec, PVOID ctx)
{
	__asm mov[esp + 0x04], eax;
	__asm mov[esp + 0x08], ebx;
	__asm mov ebp, esp;
	__asm sub ebp, 0x04;

	//
	// Check if the designated address of execution is within the proper memory bounds (Image-only execution)
	// Also prevents debug threads from being created
	// ...While preventing any other thread, such as an anti-virus DLL doing some type of in-process scan (unless exempted)
	//

	if (reinterpret_cast<std::size_t>(exec) >= callback_information.high_address ||
		reinterpret_cast<std::size_t>(exec) <= callback_information.low_address)
	{
		if (check_pairs(reinterpret_cast<std::size_t>(exec)) == true)
		{
			goto safe_exit;
		}

		//
		// Not within secure execution bounds
		//

		anticheat::hard_exit(anticheat::exit_code::thread_detection);
	}

safe_exit:
	__asm jmp[callback_information.real_cb];
}

anticheat::thread_monitor::thread_monitor(std::size_t low, std::size_t high)
{
	callback_information.low_address = low;
	callback_information.high_address = low + high;
}

void anticheat::thread_monitor::set_thread_hook()
{

	HMODULE ac_mod;
	MODULEINFO ac_mod_info;

	//
	// Get the module handle from the address of our hook 
	//

	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCTSTR>(h_ntthread_init_callback), &ac_mod);

	//
	// Get important module information, specifically for bounds checking
	//

	K32GetModuleInformation(GetCurrentProcess(), ac_mod, &ac_mod_info, sizeof(ac_mod_info));

	//
	// Except module(s) from the thread monitor 
	//

	this->lh_addr_pairs.push_back(std::make_pair(reinterpret_cast<std::size_t>(ac_mod),
		reinterpret_cast<std::size_t>(ac_mod) + ac_mod_info.SizeOfImage));

	//
	// Get information about the function we are hooking and verify its version
	//

	callback_information.real_cb = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlUserThreadStart");
	std::size_t cmp_relation = std::memcmp(callback_information.real_cb, tcallback_sig.data(), tcallback_sig.size());

	/* If it is a match to our callback version than install the hook */
	if (cmp_relation == 0)
	{
		hook_function(callback_information.real_cb, h_ntthread_init_callback, "cb:tstart");
		callback_information.real_cb = reinterpret_cast<void*>(reinterpret_cast<std::size_t>(callback_information.real_cb) + 8);
	}
}

/*++

<UNIMPLEMENTED>
Routine Description:

Marks certain pages as NO_ACCESS so that the anti-cheat can enable them

Parameters:

page - the page to mark for anti-cheat configuration
attributes - the attributes to be configured with the page marking

Return Value:

Boolean - Indicates whether a page is currently marked or not

--*/
bool anticheat::cheat_analyzer::mark_page(void* page, page_attrib& attributes)
{
	std::uint32_t old_prot;
	if (attributes.mark == true)
	{
		VirtualProtect(page, 1, attributes.state, reinterpret_cast<PDWORD>(&old_prot));
		attributes.mark = false;

	}
	else
	{
		VirtualProtect(page, 1, PAGE_NOACCESS, reinterpret_cast<PDWORD>(&attributes.state));
		attributes.mark = true;
	}
	this->page_map[page] = attributes;
	return attributes.mark;
}

/*++

<UNIMPLEMENTED>
Routine Description:

Responsible for timing notifications for page markings

Parameters:

pthis - points to a class to be used with a procedurally designed method, acting as a fake "this" pointer

Return Value:

None

--*/

void anticheat::cheat_analyzer::page_timer(void* pthis)
{
	anticheat::cheat_analyzer* __this = reinterpret_cast<cheat_analyzer*>(pthis);
	void* page = __this->page_queue.at(GetCurrentThreadId());
	page_attrib attributes = __this->page_map.at(page);

	if (attributes.time > __this->time)
	{
		Sleep(attributes.time);
	}
	else
	{
		Sleep(__this->time);
	}
	__this->mark_page(page, attributes);
}

/*++

<UNIMPLEMENTED>
Routine Description:

Used to detect arbitrary vectored exception handling

Parameters:

excptinfo - the exception information for the vectored exception (context, record), traditional signature

Return Value:

long - status code

--*/
long __stdcall anticheat::cheat_analyzer::vectored_handler(EXCEPTION_POINTERS excptinfo)
{
	return 0;
}


static std::size_t get_mod_base(const std::uint32_t pid)
{
	SetLastError(0);

	HANDLE mod_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	MODULEENTRY32W mod_entry;
	mod_entry.dwSize = sizeof(MODULEENTRY32W);

	if (mod_snap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	if (Module32FirstW(mod_snap, &mod_entry))
	{
		anticheat::close_valid_handle(mod_snap);
		if (GetLastError())
		{
			return 0;
		}
		return reinterpret_cast<std::size_t>(mod_entry.modBaseAddr);
	}

	anticheat::close_valid_handle(mod_snap);
	return 0;
}

void anticheat::cheat_analyzer::scan_signature(std::uint32_t pid)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ, FALSE, pid);
	std::vector<std::uint8_t> signature(128);
	for (std::size_t sig = 0; sig < anticheat::cheat_analyzer::signature_pairs.size(); sig++)
	{
		std::size_t bytes_written;
		std::size_t base_address = get_mod_base(pid);

		if (base_address == 0)
		{
			break;
		}

		void* ptr = reinterpret_cast<void*>(get_mod_base(pid) + anticheat::cheat_analyzer::signature_pairs[sig].first);

		if (ReadProcessMemory(process, ptr, &signature[0], anticheat::cheat_analyzer::signature_pairs[sig].second.size(),
			reinterpret_cast<SIZE_T*>(&bytes_written)) == 0)
		{
			break;
		}
		if (bytes_written != anticheat::cheat_analyzer::signature_pairs[sig].second.size())
		{
			signature.resize(anticheat::cheat_analyzer::signature_pairs[sig].second.size());
			break;
		}
		else if (std::equal(anticheat::cheat_analyzer::signature_pairs[sig].second.begin(), 
			anticheat::cheat_analyzer::signature_pairs[sig].second.end(), signature.begin()))
		{
			close_valid_handle(process);
			anticheat::hard_exit(anticheat::exit_code::process_detected);
		}
	}
	close_valid_handle(process);
}

std::pair<std::size_t, std::size_t> anticheat::pairing::acquire_module_points(const std::string& module_name)
{
	MODULEINFO mod_info;
	K32GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(module_name.c_str()), &mod_info, sizeof(mod_info));

	return std::make_pair(reinterpret_cast<std::size_t>(mod_info.lpBaseOfDll),
		reinterpret_cast<std::size_t>(mod_info.lpBaseOfDll) + mod_info.SizeOfImage);
}
