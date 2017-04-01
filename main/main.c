// vim: noet ts=4 sw=4
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "esp_wifi_types.h"
#include "nvs_flash.h"
#include "string.h"

#include "packet_defs.h"
#include "fuq.h"

const float lat = 45.5231;
const float lng = 122.6765;

fuq_queue_t reporting_queue = {0};

esp_err_t event_handler(void *ctx, system_event_t *event) {
	return ESP_OK;
}

void report_to_api(void *pv_parameter) {
	const void *report = fuq_dequeue(&reporting_queue);
	printf("Got something to report: %p\n", report);
}

void print_ssid(const wifi_pkt_beacon_payload_t *beacon_payload) {
	printf("SSID Length: %d\n", beacon_payload->ssid.len);
	char ssid_buf[32] = {0};
	const size_t ssid_len = (size_t)beacon_payload->ssid.len;
	const size_t copy_num = ssid_len > sizeof(ssid_buf) ? sizeof(ssid_buf) : ssid_len;

	memcpy(ssid_buf, beacon_payload->ssid.ssid, copy_num);
	ssid_buf[copy_num] = '\0';

	printf("SSID: %s\n", ssid_buf);
}

void process_promisc(void* buf, wifi_promiscuous_pkt_type_t type) {
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

	//const uint8_t *addr_1 = header->reciever;
	//const uint8_t *addr_2 = header->transmitter;
	//printf("Reciever: %02X:%02X:%02X:%02X:%02X:%02X\n", addr_1[0], addr_1[1], addr_1[2], addr_1[3], addr_1[4], addr_1[5]);
	//printf("Transmitter: %02X:%02X:%02X:%02X:%02X:%02X\n", addr_2[0], addr_2[1], addr_2[2], addr_2[3], addr_2[4], addr_2[5]);

	// Offsets from here:
	// https://www.savvius.com/resources/compendium/wireless_lan/wlan_packet_types
	if (header->frame_ctrl.subtype & 0x4) {
		printf("Probe request packet.\n");
	} else if (header->frame_ctrl.subtype & 0x8) {
		printf("Beacon packet.\n");
	}

	print_ssid((wifi_pkt_beacon_payload_t *)header->payload);
}

void app_main(void) {
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();

	nvs_flash_init();
	tcpip_adapter_init();

	//fuq_init(&reporting_queue);

	ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );

	ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
	ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
	ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );

	esp_wifi_set_promiscuous(true);
	esp_wifi_set_promiscuous_rx_cb(&process_promisc);

	ESP_ERROR_CHECK( esp_wifi_start() );

	//xTaskCreatePinnedToCore(&report_to_api, "report_to_api", 2048, NULL, 5, NULL, 0);
}
