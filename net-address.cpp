#include <cstdio>
#include <cstdint>
#include <cstring>
#include <netinet/in.h>
#include "net-address.h"

/* print MAC address */
void MacAddr::print_mac_addr() const {
	for (int i = 0; i < 6; i++) {
		printf("%02x", mac[i]);
		if (i != 5) printf(":");
	}
}

/* set MAC address */
int MacAddr::set_mac_addr(const char *addr) {
	uint8_t _mac[6];
	int res = sscanf(addr, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
		&_mac[0], &_mac[1], &_mac[2], &_mac[3], &_mac[4], &_mac[5]);
	
	if (res != 6) {
		fprintf(stderr, "Error: cannot convert %s to MAC address.\n", addr);
		return -1;
	}
	
	for (int i = 0; i < 6; i++) {
		mac[i] = _mac[i];
	}
	
	return 0;
}

int MacAddr::set_mac_addr(MacAddr &addr) {
	for (int i = 0; i < 6; i++) {
		mac[i] = addr.mac[i];
	}

	return 0;
}

/* Constructor of MacAddr */
MacAddr::MacAddr() {
	mac[0] = mac[1] = mac[2]
	= mac[3] = mac[4] = mac[5] = 0;
}

MacAddr::MacAddr(const char *addr) {
	set_mac_addr(addr);
}

/* Operator of MacAddr */
bool MacAddr::operator==(MacAddr &addr) {	
	bool ret = true;
	for (int i = 0; i < 6; i++) {
		ret = ret && mac[i] == addr.mac[i];
	}
	
	return ret;
}

bool MacAddr::operator==(const char *addr) {
	MacAddr mac_addr(addr);
	
	bool ret = true;
	for (int i = 0; i < 6; i++) {
		ret = ret && mac[i] == mac_addr.mac[i];
	}
	
	return ret;
}

bool MacAddr::operator<(const MacAddr &addr) const {	
	for (int i = 0; i < 6; i++) {
		if (mac[i] == addr.mac[i]) continue;
		else return mac[i] < addr.mac[i];
	}
	return false;
}


