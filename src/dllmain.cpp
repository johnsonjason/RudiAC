#include "stdafx.h"
#include "ac-bridge.h"

static std::uint32_t patch_function(void* function_va, const std::uint8_t* patch_memory, std::size_t patch_size)
{
	std::uint32_t old_protect = NULL;

	VirtualProtect(function_va, 1, PAGE_EXECUTE_READWRITE, 
		reinterpret_cast<unsigned long*>(&old_protect));

	memcpy(function_va, patch_memory, patch_size);

	VirtualProtect(function_va, 1, old_protect,
		reinterpret_cast<unsigned long*>(&old_protect));

	return GetLastError();
}


static DWORD WINAPI worker_init(LPVOID lpParam)
{
	//
	// Add a connection hook to test if this is a server with an AC side-channel
	//

	anticheat::protocol::add_conn_hook();

	anticheat::cheat_monitor* hack_daemon; 
	anticheat::thread_monitor* prcthread_daemon;

	//
	// Add an exception to the thread monitor for this module
	//

	anticheat::thread_monitor::lh_addr_pairs.push_back(anticheat::pairing::acquire_module_points("ucrtbased.dll"));

	//
	// Insert a signature into the dynamic memory signature list
	//

	anticheat::cheat_analyzer::signature_pairs.push_back(anticheat::signatures::ce_sig);

	try
	{
		//
		// Initialize the cheat_monitor with attributes for the main module 
		//

		hack_daemon = new anticheat::cheat_monitor(nullptr);

		//
		// Initialize the thread_monitor with attributes for the main module 
		//

		prcthread_daemon = new anticheat::thread_monitor(reinterpret_cast<std::size_t>(hack_daemon->module_base), hack_daemon->module_size);

		prcthread_daemon->process_scan_time = 15; // Intervals for scanning processes
		hack_daemon->time_between_scans = 15; // Intervals for the memory check
		hack_daemon->proc_mod_time = 15; // Intervals for scanning modules

		//
		// Initialize cheat_monitor features such as memory page checksums 
		//

		hack_daemon->init();

		//
		// Start the memory check scanner 
		//

		anticheat::close_valid_handle(hack_daemon->schedule(anticheat::cheat_monitor::global_scan_schedule));

		//
		// Start the process module scanner
		//

		anticheat::close_valid_handle(hack_daemon->schedule(anticheat::cheat_monitor::scan_modules));

		//
		// Start the process scanner which should never end and wait on it 
		//

		HANDLE prcscan_ref = prcthread_daemon->schedule(anticheat::thread_monitor::scan_processes);
		WaitForSingleObject(prcscan_ref, INFINITE);
		anticheat::close_valid_handle(prcscan_ref);
	}
	catch (unsigned long ac_exception_code)
	{
		return ac_exception_code;
	}

	anticheat::hard_exit(anticheat::exit_code::generic);
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	const std::uint8_t wsastartup_patch[] = { 0x81, 0xEC, 0x90, 0x01, 0x00, 0x00 };
	unsigned long wsastartup_caller = 0x00400000;
	//__62
	// wsastartup_caller += 0x274F50;
	// __83
	wsastartup_caller += 0x397BF9;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		patch_function(reinterpret_cast<void*>(wsastartup_caller), wsastartup_patch, sizeof(wsastartup_patch));
		CloseHandle(CreateThread(NULL, NULL, worker_init, NULL, NULL, NULL));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

