// vim: noet ts=4 sw=4

typedef struct  __attribute__((__packed__)) {
	unsigned protocol_version:2;
	unsigned type:2;
	unsigned subtype:4;
	unsigned nope:8;
} wifi_pkt_frame_ctrl_t;

typedef struct __attribute__((__packed__)) {
	wifi_pkt_frame_ctrl_t frame_ctrl;
	uint8_t duration[2];
	uint8_t reciever[6];
	uint8_t transmitter[6];
	uint8_t bssid[6];
	uint8_t seq_ctrl[2];
	uint8_t payload[0]; /* Pointer to start of payload area. */
} wifi_pkt_header_t;

typedef struct __attribute__((__packed__)) {
	uint8_t element_id;
	uint8_t len;
	uint8_t ssid[32]; /* Maximum of 32. */

} wifi_pkt_beacon_ssid_t;

// From here: https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/
typedef struct __attribute__((__packed__)) {
	uint8_t timestamp[8];
	uint8_t beacon_interval[2];
	uint8_t capability_interval[2];
	wifi_pkt_beacon_ssid_t ssid; /* 0-32 bytes. wat. */
} wifi_pkt_beacon_payload_t;

