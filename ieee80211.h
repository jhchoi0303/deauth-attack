#pragma pack(1)

#include "net-address.h"

struct auth_header{

	uint32_t type = 0xb0;
	uint8_t subtype = 0x00;
	uint16_t duration = 0x0000;
	MacAddr  receiver_address;
	MacAddr  transmitter_address;
	MacAddr  bss_id;
	uint16_t sequence_number = 0x1000;
	uint16_t auth_algorithm  = 0x0100;
	uint8_t auth_sequence  = 0x00;

};


struct deauth_header{

	uint32_t type = 0xc0;
	uint8_t subtype = 0x00;
	uint16_t duration = 0x0000;
	MacAddr  receiver_address;
	MacAddr  transmitter_address;
	MacAddr  bss_id;
	uint16_t sequence_number = 0x0100;
	uint16_t reason_code= 0x0007;
};
