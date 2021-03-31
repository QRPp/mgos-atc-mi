#include <errno.h>
#include <string.h>

#include <mgos.h>
#include <mgos_config.h>
#include <mgos_rpc.h>

#include <mgos-helpers/log.h>

#include <atc_mi.h>

static SLIST_HEAD(atc_mis, atc_mi) atc_mis;

bool atc_mi_add(struct atc_mi *atc_mi) {
  if (atc_mi_find(atc_mi->mac)) return false;
  SLIST_INSERT_HEAD(&atc_mis, atc_mi, entry);
  return true;
}

bool atc_mi_add_json(struct mg_str json) {
  struct atc_mi *new = atc_mi_load_json(json);
  if (!new) return false;
  if (atc_mi_add(new)) {
    LOG(LL_INFO, ("%s(): added %.*s", __FUNCTION__, json.len, json.p));
    return true;
  }
  FNERR("duplicate: %.*s", json.len, json.p);
  atc_mi_free(new);
  return false;
}

unsigned atc_mi_add_json_many(struct mg_str json) {
  unsigned loaded = 0;
  void *h = NULL;
  struct json_token v;
  while ((h = json_next_elem(json.p, json.len, h, "", NULL, &v)) != NULL)
    if (atc_mi_add_json(mg_mk_str_n(v.ptr, v.len))) loaded++;
  return loaded;
}

struct atc_mi *atc_mi_find(const uint8_t mac[6]) {
  struct atc_mi *s;
  SLIST_FOREACH(s, &atc_mis, entry) {
    if (!memcmp(s->mac, mac, sizeof(s->mac))) return s;
  }
  return NULL;
}

void atc_mi_free(struct atc_mi *old) {
  if (!old) return;
  if (old->mi_key) free(old->mi_key);
  if (old->name) free(old->name);
  free(old);
}

struct atc_mi *atc_mi_load_json(struct mg_str j) {
  struct atc_mi *new = NULL;
  void *key = NULL, *mac = NULL, *name = NULL;
  int keyL, macL, nameL;
  int ret = json_scanf(j.p, j.len, "{mac:%H,mi_key:%H,name:%Q}", &macL, &mac,
                       &keyL, &key, &name, &nameL);
  if (ret < 0)
    FNERR("json_scanf(%.*s): %d", j.len, j.p, ret);
  else if (!mac)
    FNERR("no mac: %.*s", j.len, j.p);
  else if (macL != sizeof(new->mac))
    FNERR("need %u byte %s: %.*s", sizeof(new->mac), "mac", j.len, j.p);
  else if (key && keyL != sizeof(*new->mi_key))
    FNERR("need %u byte %s: %.*s", sizeof(*new->mi_key), "mi_key", j.len, j.p);
  else if (!(new = malloc(sizeof(*new))))
    FNERR("%s(%u): %s", "malloc", sizeof(*new), strerror(errno));
  else {
    memcpy(new->mac, mac, sizeof(new->mac));
    new->mi_key = key;
    key = NULL;
    new->name = name;
    name = NULL;
    new->user_data = NULL;
  }
  if (key) free(key);
  if (mac) free(mac);
  if (name) free(name);
  return new;
}

unsigned atc_mi_purge() {
  unsigned purged;
  for (purged = 0; !SLIST_EMPTY(&atc_mis); purged++) {
    struct atc_mi *head = SLIST_FIRST(&atc_mis);
    SLIST_REMOVE_HEAD(&atc_mis, entry);
    atc_mi_free(head);
  }
  return purged;
}

static void atc_mi_load_sensors_handler(struct mg_rpc_request_info *ri,
                                        void *cb_arg,
                                        struct mg_rpc_frame_info *fi,
                                        struct mg_str args) {
  mg_rpc_send_responsef(
      ri, "{loaded:%u}",
      atc_mi_add_json_many(
          args.len ? args : mg_mk_str(mgos_sys_config_get_atc_mi_list())));
}

static void atc_mi_purge_sensors_handler(struct mg_rpc_request_info *ri,
                                         void *cb_arg,
                                         struct mg_rpc_frame_info *fi,
                                         struct mg_str args) {
  mg_rpc_send_responsef(ri, "{purged:%u}", atc_mi_purge());
}

void atc_mi_sensors_init() {
  SLIST_INIT(&atc_mis);
  atc_mi_add_json_many(mg_mk_str(mgos_sys_config_get_atc_mi_list()));
  mg_rpc_add_handler(mgos_rpc_get_global(), "AtcMi.LoadSensors", "",
                     atc_mi_load_sensors_handler, NULL);
  mg_rpc_add_handler(mgos_rpc_get_global(), "AtcMi.PurgeSensors", "",
                     atc_mi_purge_sensors_handler, NULL);
}
