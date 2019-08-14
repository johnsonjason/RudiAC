#pragma once
#ifndef CHEAT_MONITOR
#define CHEAT_MONITOR
// cheat-monitor.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "error-checking.h"
#include "chooks.h"
#include <Windows.h>
#include <Psapi.h>
#include <process.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <array>
#include <iostream>
#include <unordered_map>

namespace anticheat
{
	typedef char image_name[260];
	typedef void nonce;
	typedef unsigned long ulnonce;

	typedef enum _accessibility
	{
		null = PAGE_NOACCESS,
		execute = PAGE_EXECUTE,
		read = PAGE_READONLY,
		read_write = PAGE_READWRITE,
		read_write_execute = PAGE_EXECUTE_READWRITE,
		read_execute = PAGE_EXECUTE_READ,
		execute_wcopy = PAGE_EXECUTE_WRITECOPY
	} accessibility;

	typedef enum _nonce_code
	{
		nonce_null = 0,
		init = 1,
		hash = 2,
		scan = 3
	} nonce_code;

	typedef enum _scan_state
	{
		scan_null = 0,
		ready = 1,
		suspend = 2,
		wait = 3,
		run = 4
	} scan_state;

	typedef enum _exit_code
	{
		generic,
		process_detected,
		module_detected,
		memory_detected,
		debug_detected,
		thread_detection,
		hook_detected
	} exit_code;

	enum module_exception
	{
		mod_info_failure,
		mod_name_failure
	};

	enum dbgp_env
	{
		being_debugged = 0x02,
		nt_globalflag = 0x68
	};

	enum nonce_exception
	{
		ran,
		out_of_range
	};

	typedef struct _bad_thread_ctx
	{
		void* address;
		void* thread_module_base;
		char thread_module_name[260];
	} bad_thread_ctx;

	typedef struct _reg_thread_cb_data
	{
		void* real_cb;
		std::size_t low_address;
		std::size_t high_address;
	} reg_thread_cb_data;

	typedef struct _page_unit
	{
		void* page_address;
		std::size_t size;
		std::vector<std::uint8_t> fault_container;
		anticheat::accessibility access;
		error_checking::crc_hash page_checksum;
	} page_unit;

	typedef struct _page_attrib
	{
		std::uint32_t state;
		bool mark;
		std::size_t time;
	} page_attrib;

	inline void close_valid_handle(HANDLE reference);
	__declspec(noinline) void hard_exit(anticheat::exit_code reason);
	void sleep_time(std::size_t time);

	class cheat_monitor
	{
	public:
		cheat_monitor(LPCSTR mod);
		anticheat::nonce init();
		static anticheat::ulnonce __stdcall global_start_scan(void* pthis); // Execute as new thread
		static anticheat::ulnonce __stdcall global_scan_schedule(void* pthis); // Execute as new thread
		static anticheat::ulnonce __stdcall scan_modules(void* pthis);
		void global_stop_scan(std::size_t time);
		HANDLE schedule(PTHREAD_START_ROUTINE routine);
		std::size_t time_between_scans;
		std::size_t proc_mod_time;
		std::size_t module_size;
		void* module_base;

	protected:
		std::vector<anticheat::page_unit> module_pages;
		char module_name[260];

	private:
		anticheat::scan_state scan_stop;
		std::size_t stop_time;
		CRITICAL_SECTION scan_section;
		CONDITION_VARIABLE scan_condition;
		HANDLE scan_thread;
		std::size_t scan_cycles;
		std::array<anticheat::nonce_code, 4> nonce_container;

		anticheat::nonce calc_vpt_hashes();
		void flag_nonce(anticheat::nonce_code code);
		void check_pages(const std::vector<anticheat::page_unit>& pages);
		void global_restart_scan();
	};

	class thread_monitor
	{
	public:
		thread_monitor(std::size_t low, std::size_t high);
		void set_thread_hook();
		static anticheat::ulnonce __stdcall scan_processes(void* pthis);
		HANDLE schedule(PTHREAD_START_ROUTINE routine);
		static std::vector<std::pair<std::size_t, std::size_t>> lh_addr_pairs;
		std::size_t process_scan_time;
		std::size_t process_snap_time;

	private:
		std::array<anticheat::nonce_code, 2> thread_nonce_container;

		//
		// TODO
		//RtlUserThreadStart hook - monitor which threads were called with CreateThreadand are in the range of our PE image
		// Add CreateThread hook to maintain a database of internal process threads
		// Monitor snapshots intermittently for th32OwnerProcessID to check if the thread is part of our process
		//
	};

	class cheat_analyzer
	{
	public:
		cheat_analyzer();

		bool mark_page(void* page, page_attrib& attributes);
		bool unmark_page(void* page, page_attrib& attributes);
		static void scan_signature(std::uint32_t process_id);
		static void page_timer(void* pthis);
		static long __stdcall vectored_handler(EXCEPTION_POINTERS excptinfo);
		static std::vector<std::pair<std::size_t, std::vector<std::uint8_t>>> signature_pairs;

	private:
		std::size_t time;
		std::unordered_map<void*, anticheat::page_attrib> page_map;
		std::unordered_map<std::uint32_t, void*> page_queue;
	};

	const std::uint8_t jmphook_instr = 0xE9;
	const std::uint8_t callhook_instr = 0xE8;

	namespace signatures
	{
		static std::pair<std::size_t, std::vector<std::uint8_t>> ce_sig =
		{
			0x5050, { 0x83, 0x38, 0x00, 0x74, 0x36, 0x56, 0x8B, 0x30, 0x83, 
			0xEE, 0x0C, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x83, 0x7E, 0x04, 0x00,
			0x7C, 0x23, 0x83, 0x3D, 0x30, 0xE0, 0x8B, 0x00, 0x00 }
		};
	}

	namespace pairing
	{
		std::pair<std::size_t, std::size_t> acquire_module_points(const std::string& module_name);
	}
}


#endif CHEAT_MONITOR
