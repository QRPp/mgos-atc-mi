#include <stdbool.h>

void atc_mi_ble_scan_init();
void atc_mi_decode_init();
void atc_mi_sensors_init();

bool mgos_atc_mi_init(void) {
  atc_mi_decode_init();
  atc_mi_sensors_init();
  atc_mi_ble_scan_init();
  return true;
}
