#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <common/mg_str.h>
#include <common/queue.h>
#include <mgos_bt_gap.h>

#define ATC_MI_EVENT_DATA MGOS_EVENT_BASE('A', 'T', 'C')

struct atc_mi {
  SLIST_ENTRY(atc_mi) entry;
  uint8_t mac[6];
  uint8_t (*mi_key)[16];
  char *name;
  void *user_data;
};

bool atc_mi_add(struct atc_mi *atc_mi);
struct atc_mi *atc_mi_add_json(struct json_token v);
unsigned atc_mi_add_json_many(struct mg_str json);
struct atc_mi *atc_mi_find(const uint8_t mac[6]);
void atc_mi_free(struct atc_mi *atc_mi);
struct atc_mi *atc_mi_load_json(struct json_token v);
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

struct atc_mi_event_data {
  const struct mgos_bt_gap_scan_result *res;
  struct atc_mi *atc_mi;
  const char *fmt;
  const struct atc_mi_data *data;
};
