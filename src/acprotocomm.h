#ifndef AC_PROTOCOMM
#define AC_PROTOCOMM
#include <winsock2.h>
#include "chooks.h"
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

namespace anticheat
{
	namespace protocol
	{
		void add_conn_hook();
		void destroy_conn_hook();
		int __stdcall h_connect(SOCKET socket, const sockaddr* addr, int len);
	}
}


#endif

