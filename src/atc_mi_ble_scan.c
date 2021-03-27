#include <mgos.h>
#include <mgos_bt_gap.h>
#include <mgos_config.h>

#include <atc_mi.h>

static void adv_handle(int ev, void *ev_data, void *userdata) {
  if (ev != MGOS_BT_GAP_EVENT_SCAN_RESULT) return;
  atc_mi_handle(ev_data);
}

static void scan_start(int ev, void *ev_data, void *userdata) {
  if (ev != MGOS_BT_GAP_EVENT_SCAN_STOP) return;
  struct mgos_bt_gap_scan_opts opts = {
      .duration_ms = 59999,
      .active = mgos_sys_config_get_atc_mi_ble_scan_active()};
  if (!mgos_bt_gap_scan(&opts)) LOG(LL_ERROR, ("BT scan: failed to start"));
}

void atc_mi_ble_scan_init() {
  if (!mgos_sys_config_get_atc_mi_ble_scan()) return;
  mgos_event_add_group_handler(MGOS_BT_GAP_EVENT_SCAN_RESULT, adv_handle, NULL);
  mgos_event_add_group_handler(MGOS_BT_GAP_EVENT_SCAN_STOP, scan_start, NULL);
  scan_start(MGOS_BT_GAP_EVENT_SCAN_STOP, NULL, NULL);
}
