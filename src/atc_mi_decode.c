#include <stdint.h>

#include <endian.h>

#include <mbedtls/ccm.h>
#include <mbedtls/error.h>
#include <mgos.h>
#include <mgos_bt.h>
#include <mgos_bt_gap.h>

#include <mgos-helpers/json.h>

#include <atc_mi.h>

// {{{1 Sundry
struct __attribute__((packed)) ble_adv_chunk_hdr {
  uint8_t len;
  uint8_t type;
};

static struct mbedtls_ccm_context ccm;

#define JSON_PRINTF_AND_MBEDTLS(out, err, fmt, ...) \
  do {                                              \
    char buf[128];                                  \
    mbedtls_strerror(err, buf, sizeof(buf));        \
    json_printf(out, fmt, ##__VA_ARGS__, buf);      \
  } while (0)

static uint8_t *maccpy_reverse(uint8_t dst[6], uint8_t src[6]) {
  for (int i = 0; i < 6; i++) dst[i] = src[5 - i];
  return dst;
}

static void src_log_if_diff_mac(struct mgos_bt_addr *src, uint8_t mac[6],
                                struct json_out *out) {
  if (!mac || !memcmp(src->addr, mac, sizeof(src->addr))) return;
  const char *str = mgos_bt_addr_to_str(src, 0, alloca(MGOS_BT_ADDR_STR_LEN));
  json_printf(out, " (%s %s)", "src", str);
}

// {{{1 ATC pvvx
#define ATC_UUID 0x181a
struct __attribute__((packed)) atc_pvvx {
  struct ble_adv_chunk_hdr hdr;  // { type: MGOS_BT_GAP_EIR_SERVICE_DATA_16 }
  uint16_t uuid;       // ATC_UUID: `Environmental Sensing' GATT service
  uint8_t mac[6];      // source MAC
  int16_t temp_cC;     // temperature (centidegrees Celsius)
  uint16_t humi_cPct;  // relative humidity (centipercentage)
  uint16_t batt_mV;    // battery level (mV)
  uint8_t batt_pct;    // battery level (percentage)
  uint8_t cnt;         // measurement counter
  uint8_t flags;       // ATC/pvvx trigger flags
};

static bool ble_adv_atc_pvvx_decode(struct mgos_bt_gap_scan_result *r,
                                    struct atc_mi *atc_mi,
                                    struct atc_mi_data *data,
                                    struct json_out *ok,
                                    struct json_out *fail) {
  struct atc_pvvx *adv = (struct atc_pvvx *) r->adv_data.p;
  data->cnt = adv->cnt;
  data->temp_cC = le16toh(adv->temp_cC);
  data->humi_cPct = le16toh(adv->humi_cPct);
  data->batt_mV = le16toh(adv->batt_mV);
  data->batt_pct = adv->batt_pct;
  data->flags = adv->flags;
  if (!ok) return true;
  json_printf(ok, "%c %.2f%s, %c %.2f%%, %c %u%% (%u %s), # %u, %s %x", 'T',
              data->temp_cC / 100.0, "°C", 'H', data->humi_cPct / 100.0, 'B',
              data->batt_pct, data->batt_mV, "mv", data->cnt, "flg",
              data->flags);
  src_log_if_diff_mac(&r->addr, data->mac, ok);
  return true;
}

static bool ble_adv_atc_pvvx_detect(struct mgos_bt_gap_scan_result *r) {
  struct atc_pvvx *adv = (void *) r->adv_data.p;
  return r->adv_data.len == sizeof(*adv) && adv->hdr.len == sizeof(*adv) - 1 &&
         adv->hdr.type == MGOS_BT_GAP_EIR_SERVICE_DATA_16 &&
         le16toh(adv->uuid) == ATC_UUID;
}

static uint8_t *ble_adv_atc_pvvx_mac(struct mgos_bt_gap_scan_result *r,
                                     struct atc_mi_data *data) {
  return maccpy_reverse(data->mac, ((struct atc_pvvx *) r->adv_data.p)->mac);
}

// {{{1 MI encrypted
#define MI_ENC_EXC_CT (sizeof(struct mi_enc_top) + sizeof(struct mi_enc_bottom))
#define MI_ENC_B_LEN (MI_ENC_EXC_CT + MI_ENC_CT_B_LEN)
#define MI_ENC_TH_LEN (MI_ENC_EXC_CT + MI_ENC_CT_TH_LEN)
#define MI_ENC_UUID 0xfe95
#define MI_ENC_FCTL 0x5858
#define MI_ENC_DEV 0x055b
struct __attribute__((packed)) mi_enc_top {
  struct ble_adv_chunk_hdr hdr;  // { type: MGOS_BT_GAP_EIR_SERVICE_DATA_16 }
  uint16_t uuid;                 // MI_ENC_UUID
  uint16_t frame_ctl;            // MI_ENC_FCTL
  uint16_t dev_type;             // MI_ENC_DEV
  uint8_t cnt_lsb;               // LSB of 32-bit frame counter
  uint8_t mac[6];                // source MAC
};

#define MI_ENC_CT_B_LEN 4
#define MI_ENC_CT_TH_LEN 5

struct __attribute__((packed)) mi_enc_bottom {
  uint8_t cnt_msb[3];  // 3 MSB of 32-bit frame counter
  uint8_t mac_tag[4];  // encrypted message auth code
};

struct __attribute__((packed)) mi_enc_flags {
  struct ble_adv_chunk_hdr hdr;  // { type: MGOS_BT_GAP_EIR_FLAGS }
  uint8_t flags;
};

struct __attribute__((packed)) mi_enc_iv {
  uint8_t mac[6];
  uint16_t dev_type;
  uint32_t cnt;
};

struct __attribute__((packed)) mi_enc_pt {
  uint16_t type;
  uint8_t len;
  union {
    uint8_t batt_pct;
    uint16_t humi_dPct;
    int16_t temp_dC;
  };
};

#define FAIL_UNLESS_MBEDTLS(fn, ...)                                         \
  do {                                                                       \
    int ret = fn(__VA_ARGS__);                                               \
    if (!ret) break;                                                         \
    if (fail) JSON_PRINTF_AND_MBEDTLS(fail, ret, "%s(): [%d] %s", #fn, ret); \
    return false;                                                            \
  } while (0)
#define FAIL_WITH(fmt, ...)                          \
  do {                                               \
    if (fail) json_printf(fail, fmt, ##__VA_ARGS__); \
    return false;                                    \
  } while (0)
#define SUCCEED_WITH(fmt, ...)                               \
  do {                                                       \
    if (!ok) return true;                                    \
    json_printf(ok, fmt ", # %u", ##__VA_ARGS__, data->cnt); \
    goto success;                                            \
  } while (0)
static bool ble_adv_mi_enc_decode(struct mgos_bt_gap_scan_result *r,
                                  struct atc_mi *atc_mi,
                                  struct atc_mi_data *data, struct json_out *ok,
                                  struct json_out *fail) {
  if (!atc_mi) FAIL_WITH("%s", "not listed, no key");
  if (!atc_mi->mi_key) FAIL_WITH("%s", "no key");
  FAIL_UNLESS_MBEDTLS(mbedtls_ccm_setkey, &ccm, MBEDTLS_CIPHER_ID_AES,
                      *atc_mi->mi_key, sizeof(*atc_mi->mi_key) * 8);

  struct mi_enc_top *top = (void *) &((struct mi_enc_flags *) r->adv_data.p)[1];
  uint8_t ctL = top->hdr.len + 1 - MI_ENC_EXC_CT;
  struct mi_enc_bottom *bottom = ((void *) &top[1]) + ctL;

  union {
    uint32_t all;
    struct {
      uint8_t lsb, msb[sizeof(bottom->cnt_msb)];
    };
  } cnt = {.lsb = top->cnt_lsb};
  memcpy(cnt.msb, bottom->cnt_msb, sizeof(cnt.msb));

  uint8_t aad = 0x11;
  struct mi_enc_iv iv = {.dev_type = top->dev_type, .cnt = cnt.all};
  memcpy(iv.mac, top->mac, sizeof(iv.mac));
  struct mi_enc_pt pt;

  data->temp_cC = ATC_MI_DATA_TEMP_CC_INVAL;
  data->humi_cPct = ATC_MI_DATA_HUMI_CPCT_INVAL;
  data->batt_mV = ATC_MI_DATA_BATT_MV_INVAL;
  data->batt_pct = ATC_MI_DATA_BATT_PCT_INVAL;
  data->flags = ATC_MI_DATA_FLAGS_INVAL;
  FAIL_UNLESS_MBEDTLS(mbedtls_ccm_auth_decrypt, &ccm, ctL, (void *) &iv,
                      sizeof(iv), &aad, sizeof(aad), (void *) &top[1],
                      (void *) &pt, (void *) bottom->mac_tag,
                      sizeof(bottom->mac_tag));
  if (pt.len != ctL - offsetof(struct mi_enc_pt, temp_dC)) goto invalid_pt;

  data->cnt = le32toh(cnt.all);
  switch (le16toh(pt.type)) {
    case 0x1004:
      if (pt.len != sizeof(pt.temp_dC)) goto invalid_pt;
      data->temp_cC = (int16_t) le16toh(pt.temp_dC) * 10;
      SUCCEED_WITH("%c %.1f%s", 'T', data->temp_cC / 100.0, "°C");
    case 0x1006:
      if (pt.len != sizeof(pt.humi_dPct)) goto invalid_pt;
      data->humi_cPct = le16toh(pt.humi_dPct) * 10;
      SUCCEED_WITH("%c %.1f%%", 'H', data->humi_cPct / 100.0);
    case 0x100a:
      if (pt.len != sizeof(pt.batt_pct)) goto invalid_pt;
      // data->batt_mV = 2200 + 9 * pt.batt_pct;
      data->batt_pct = pt.batt_pct;
      SUCCEED_WITH("%c %u%%", 'B', data->batt_pct);
  }

invalid_pt:
  ctL -= offsetof(struct mi_enc_pt, batt_pct);
  FAIL_WITH("%s %04x %02x %0*x", "invalid pt", le16toh(pt.type), pt.len,
            ctL == sizeof(pt.batt_pct) ? sizeof(pt.batt_pct) * 2
                                       : sizeof(pt.humi_dPct) * 2,
            ctL == sizeof(pt.batt_pct) ? pt.batt_pct : le16toh(pt.humi_dPct));

success:
  src_log_if_diff_mac(&r->addr, data->mac, ok);
  return true;
}
#undef FAIL_UNLESS_MBEDTLS
#undef FAIL_WITH
#undef SUCCEED_WITH

static bool ble_adv_mi_enc_detect(struct mgos_bt_gap_scan_result *r) {
  struct mi_enc_flags *flags = (struct mi_enc_flags *) r->adv_data.p;
  struct mi_enc_top *top = (struct mi_enc_top *) (flags + 1);
  return (r->adv_data.len == sizeof(*flags) + MI_ENC_B_LEN ||
          r->adv_data.len == sizeof(*flags) + MI_ENC_TH_LEN) &&
         flags->hdr.len == sizeof(*flags) - 1 &&
         flags->hdr.type == MGOS_BT_GAP_EIR_FLAGS &&
         top->hdr.len == r->adv_data.len - sizeof(*flags) - 1 &&
         top->hdr.type == MGOS_BT_GAP_EIR_SERVICE_DATA_16 &&
         le16toh(top->uuid) == MI_ENC_UUID &&
         le16toh(top->frame_ctl) == MI_ENC_FCTL &&
         le16toh(top->dev_type) == MI_ENC_DEV;
}

static uint8_t *ble_adv_mi_enc_mac(struct mgos_bt_gap_scan_result *r,
                                   struct atc_mi_data *data) {
  struct mi_enc_top *top = (void *) &((struct mi_enc_flags *) r->adv_data.p)[1];
  return maccpy_reverse(data->mac, top->mac);
}

// {{{1 Dispatching
#define FMT(name, pfx) \
  { name, pfx##_decode, pfx##_detect, pfx##_mac }
struct atc_mi_fmt {
  const char *name;
  bool (*decode)(struct mgos_bt_gap_scan_result *r, struct atc_mi *atc_mi,
                 struct atc_mi_data *data, struct json_out *ok,
                 struct json_out *fail);
  bool (*detect)(struct mgos_bt_gap_scan_result *r);
  uint8_t *(*mac)(struct mgos_bt_gap_scan_result *r, struct atc_mi_data *data);
} formats[] = {
    FMT("ATC/pvvx", ble_adv_atc_pvvx), FMT("MI ENC", ble_adv_mi_enc), {NULL}};
#undef FMT

static void ble_adv_log(struct mgos_bt_gap_scan_result *r, const uint8_t mac[6],
                        struct atc_mi_fmt *fmt, struct atc_mi *atc_mi,
                        const char *reason, const char *detail) {
  const struct mgos_bt_addr *addr = (void *) mac ?: &r->addr;
  LOG(LL_INFO, ("%s:%s%s (%s%s%s%s rssi %d)%s%s", reason, fmt ? " " : "",
                fmt ? fmt->name : "",
                mgos_bt_addr_to_str(addr, 0, alloca(MGOS_BT_ADDR_STR_LEN)),
                atc_mi && atc_mi->name ? " \"" : "",
                atc_mi && atc_mi->name ? atc_mi->name : "",
                atc_mi && atc_mi->name ? "\"" : "", r->rssi, detail ? ": " : "",
                detail ?: ""));
}

static void ble_adv_log_raw(struct mgos_bt_gap_scan_result *r) {
  struct json_out *out = JSON_OUT_BUFA(256);
  json_printf(out, "%s %H", "adv", (int) r->adv_data.len, r->adv_data.p);
  if (r->scan_rsp.len && mgos_sys_config_get_bt_scan_active()) {
    json_printf(out, ", %s %H", "rsp", (int) r->scan_rsp.len, r->scan_rsp.p);
    struct mg_str name = mgos_bt_gap_parse_name(r->scan_rsp);
    if (name.p) json_printf(out, ", %s %.*Q", "name", (int) name.len, name.p);
  }
  ble_adv_log(r, NULL, NULL, NULL, "raw", out->u.buf.buf);
}

static void atc_mi_handle(int ev, void *ev_data, void *userdata) {
  if (ev != MGOS_BT_GAP_EVENT_SCAN_RESULT) return;

  struct mgos_bt_gap_scan_result *r = ev_data;
  if (mgos_sys_config_get_atc_mi_debug_raw()) ble_adv_log_raw(r);

  struct atc_mi_fmt *fmt = formats;
  while (fmt->name && !fmt->detect(r)) fmt++;
  if (!fmt->name) return;

  struct atc_mi_data data;
  const uint8_t *mac = fmt->mac(r, &data);
  struct atc_mi *atc_mi = atc_mi_find(mac ?: r->addr.addr);
  if (!atc_mi && !mgos_sys_config_get_atc_mi_any()) {
    if (mgos_sys_config_get_atc_mi_debug_rejected())
      ble_adv_log(r, mac, fmt, NULL, "rejected", NULL);
    return;
  }

  struct json_out *ok = NULL, *fail = NULL;
  if (mgos_sys_config_get_atc_mi_debug_accepted()) ok = JSON_OUT_BUFA(128);
  if (mgos_sys_config_get_atc_mi_debug_failed()) fail = JSON_OUT_BUFA(128);
  if (!fmt->decode(r, atc_mi, &data, ok, fail)) {
    if (fail) ble_adv_log(r, mac, fmt, atc_mi, "failed", fail->u.buf.buf);
    return;
  }

  if (ok) ble_adv_log(r, mac, fmt, atc_mi, "accepted", ok->u.buf.buf);
  struct atc_mi_event_data amed = {
      .res = r, .atc_mi = atc_mi, .fmt = fmt->name, .data = &data};
  mgos_event_trigger(ATC_MI_EVENT_DATA, &amed);
}

void atc_mi_decode_init() {
  mbedtls_ccm_init(&ccm);
  mgos_event_register_base(ATC_MI_EVENT_DATA, "atc-mi");
  mgos_event_add_group_handler(MGOS_BT_GAP_EVENT_SCAN_RESULT, atc_mi_handle,
                               NULL);
}
