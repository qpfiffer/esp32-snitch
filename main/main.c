// vim: noet ts=4 sw=4
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_wifi_types.h"
#include "nvs_flash.h"
#include "string.h"

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

esp_err_t event_handler(void *ctx, system_event_t *event)
{
	return ESP_OK;
}

void process_promisc(void* buf, wifi_promiscuous_pkt_type_t type)
{
	switch (type) {
		case WIFI_PKT_DATA:
		case WIFI_PKT_MISC:
		case WIFI_PKT_CTRL:
			return;
		case WIFI_PKT_MGMT:
			// Beacon, Probe and Probe Response frames.
			break;
	}
	const wifi_promiscuous_pkt_t *packet = buf;
	//const unsigned int packet_siz = packet->rx_ctrl.sig_len;
	//const unsigned int timestamp = packet->rx_ctrl.timestamp;

	const wifi_pkt_header_t *header = (wifi_pkt_header_t *)packet->payload;

	const uint8_t *addr_1 = header->reciever;
	const uint8_t *addr_2 = header->transmitter;
	printf("Reciever: %02X:%02X:%02X:%02X:%02X:%02X\n", addr_1[0], addr_1[1], addr_1[2], addr_1[3], addr_1[4], addr_1[5]);
	printf("Transmitter: %02X:%02X:%02X:%02X:%02X:%02X\n", addr_2[0], addr_2[1], addr_2[2], addr_2[3], addr_2[4], addr_2[5]);

	// Offsets from here:
	// https://www.savvius.com/resources/compendium/wireless_lan/wlan_packet_types
	if (header->frame_ctrl.subtype & 0x4)
		printf("Probe request packet.\n");
	else if (header->frame_ctrl.subtype & 0x5)
		printf("Probe response packet.\n");
	else if (header->frame_ctrl.subtype & 0x8) {
		printf("Beacon packet.\n");
		const wifi_pkt_beacon_payload_t *beacon_payload = (wifi_pkt_beacon_payload_t *)header->payload;
		printf("SSID Length: %d\n", beacon_payload->ssid.len);
		char ssid_buf[32] = {0};
		const size_t ssid_len = (size_t)beacon_payload->ssid.len;
		const size_t copy_num = ssid_len > sizeof(ssid_buf) ? sizeof(ssid_buf) : ssid_len;

		memcpy(ssid_buf, beacon_payload->ssid.ssid, copy_num);
		ssid_buf[copy_num] = '\0';

		printf("SSID(?): %s\n", ssid_buf);
	}
}

void app_main(void)
{
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	nvs_flash_init();
	tcpip_adapter_init();
	ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );

	ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );

	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&process_promisc);

	ESP_ERROR_CHECK( esp_wifi_start() );
}
