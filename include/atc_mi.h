#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <common/mg_str.h>
#include <common/queue.h>
#include <mgos_bt_gap.h>

#ifdef __cplusplus
extern "C" {
#endif

struct atc_mi {
  SLIST_ENTRY(atc_mi) entry;
  uint8_t mac[6];
  uint8_t (*mi_key)[16];
  char *name;
  void *user_data;
};

bool atc_mi_add(struct atc_mi *atc_mi);
bool atc_mi_add_json(struct mg_str json);
unsigned atc_mi_add_json_many(struct mg_str json);
struct atc_mi *atc_mi_find(const uint8_t mac[6]);
void atc_mi_free(struct atc_mi *atc_mi);
struct atc_mi *atc_mi_load_json(struct mg_str json);
unsigned atc_mi_purge();

#define ATC_MI_DATA_TEMP_CC_INVAL INT16_MAX
#define ATC_MI_DATA_HUMI_CPCT_INVAL UINT16_MAX
#define ATC_MI_DATA_BATT_MV_INVAL UINT16_MAX
#define ATC_MI_DATA_BATT_PCT_INVAL UINT8_MAX
#define ATC_MI_DATA_FLAGS_INVAL UINT8_MAX

struct atc_mi_data {
  uint8_t mac[6];      // MAC from the advertisement data (network order)
  uint32_t cnt;        // measurement counter
  int16_t temp_cC;     // temperature (centidegrees Celsius)
  uint16_t humi_cPct;  // relative humidity (centipercentage)
  uint16_t batt_mV;    // battery level (mV)
  uint8_t batt_pct;    // battery level (percentage)
  uint8_t flags;       // ATC/pvvx trigger flags
};

typedef void (*atc_mi_data_sink)(uint8_t mac[6], struct atc_mi *atc_mi,
                                 const char *fmt, struct atc_mi_data *data,
                                 void *opaque);
void atc_mi_handle(struct mgos_bt_gap_scan_result *r);
void atc_mi_set_sink(atc_mi_data_sink cb, void *opaque);

#ifdef __cplusplus
}
#endif
