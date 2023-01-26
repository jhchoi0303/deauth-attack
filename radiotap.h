#pragma pack(1)

struct radiotap_header {
    uint8_t version = 0x00;
    uint8_t pad = 0x00;
    uint16_t len = 0x000c;
    uint32_t present_flags = 0x008004;
    uint32_t data = 0x020018;
};

enum radiotap_present_flags {
	TSFT,
	FLAGS,
	RATE,
	CHANNEL,
	FHSS,
	DBM_ANTENNA_SIGNAL,
	DBM_ANTENNA_NOISE,
	LOCK_QUALITY,
	TX_ATTENUATION,
	DB_TX_ATTENUATION,
	DBM_TX_POWER,
	ANTENNA,
	DB_ANTENNA_SIGNAL,
	DB_ANTENNA_NOISE,
	RX_FLAGS,
	TX_FLAGS,
	RESERVED16,
	RESERVED17,
	CHANNEL_PLUS,
	MCS_INFORMATION,
	A_MPDU_STATUS,
	VHT_INFORMATION,
	FRAME_TIMESTAMP,
	HE_INFORMATION,
	HE_MU_INFORMATION,
	RESERVED25,
	ZERO_LENGTH_PSDU,
	L_SIG,
	TLVS,
	RADIOTAP_NS_NEXT,
	VENDOR_NS_NEXT,
	EXT
};