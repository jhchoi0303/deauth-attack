/* Constants */
enum {
	MAC_ADDR_SIZE = 6
};

/* MAC Address */
#pragma pack(push, 1)
class MacAddr {
public:
	uint8_t mac[6];
 
	void print_mac_addr() const;
	int set_mac_addr(const char *addr);
	int set_mac_addr(MacAddr &addr);

	MacAddr();
	MacAddr(const char *addr);
	bool operator==(MacAddr &addr);
	bool operator==(const char *addr);
	bool operator<(const MacAddr &addr) const;
};
#pragma pack(pop)


