#include "stdafx.h"
#include "acprotocomm.h"

#pragma warning( disable : 4996)
#define PKT_AC_HDR 0x05, 0x09
#define PKT_AC_SEGMENT 0x01, 0x03, 0x03, 0x07
#define PKT_AC_EXTEND 0x09, 0xC8

const char packet_t[] = { PKT_AC_HDR, PKT_AC_SEGMENT, PKT_AC_EXTEND };
std::vector<std::string> ipa_whitelist = 
{

};

//
// Stub
//

static bool check_whitelist(const sockaddr* sa)
{
	if (sa->sa_family != AF_INET)
	{
		return false;
	}

	SOCKADDR_IN* socket_address = const_cast<SOCKADDR_IN*>(reinterpret_cast<const SOCKADDR_IN*>(sa));
	char* buf = inet_ntoa(socket_address->sin_addr);
	char buf2[17];

	strcpy(buf2, buf);
	std::string current_ipa(buf2);

	if (!ipa_whitelist.empty())
	{
		for (const std::string& ipa : ipa_whitelist)
		{
			if (current_ipa == ipa)
			{
				return true;
			}
		}
	}

	return false;
}

int __stdcall anticheat::protocol::h_connect(SOCKET socket, const sockaddr* addr, int len)
{
	if (check_whitelist(addr))
	{
		temp_unhook_function("ws2_32:connect");
		int ret_value = connect(socket, addr, len);
		rehook_function("ws2_32:connect");
		send(socket, packet_t, sizeof(packet_t), 0);
		return ret_value;
	}
	else
	{
		temp_unhook_function("ws2_32:connect");
		int ret_value = connect(socket, addr, len);
		rehook_function("ws2_32:connect");
		return ret_value;
	}
}

void anticheat::protocol::add_conn_hook()
{
	hook_function(GetProcAddress(GetModuleHandleA("ws2_32.dll"), "connect"), h_connect, "ws2_32:connect");
}

void anticheat::protocol::destroy_conn_hook()
{
	unhook_function("ws2_32:connect");
}
