#include <errno.h>
#include <string.h>

#include <mgos.h>
#include <mgos_config.h>

#include <mgos-helpers/log.h>

#include <atc_mi.h>

static SLIST_HEAD(atc_mis, atc_mi) atc_mis;

bool atc_mi_add(struct atc_mi *atc_mi) {
  if (atc_mi_find(atc_mi->mac)) return false;
  SLIST_INSERT_HEAD(&atc_mis, atc_mi, entry);
  return true;
}

bool atc_mi_add_json(struct json_token v) {
  struct atc_mi *new = atc_mi_load_json(v);
  if (!new) return false;
  if (atc_mi_add(new)) {
    LOG(LL_INFO, ("%s(): added %.*s", __FUNCTION__, v.len, v.ptr));
    return true;
  }
  FNERR("duplicate: %.*s", v.len, v.ptr);
  atc_mi_free(new);
  return false;
}

unsigned atc_mi_add_json_many(struct mg_str json) {
  unsigned loaded = 0;
  void *h = NULL;
  struct json_token v;
  while ((h = json_next_elem(json.p, json.len, h, "", NULL, &v)) != NULL)
    if (atc_mi_add_json(v)) loaded++;
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

struct atc_mi *atc_mi_load_json(struct json_token v) {
  struct atc_mi *new = NULL;
  void *key = NULL, *mac = NULL, *name = NULL;
  int keyL, macL, nameL;
  int ret = json_scanf(v.ptr, v.len, "{mac:%H,mi_key:%H,name:%Q}", &macL, &mac,
                       &keyL, &key, &name, &nameL);
  if (ret < 0)
    FNERR("json_scanf(%.*s): %d", v.len, v.ptr, ret);
  else if (!mac)
    FNERR("no mac: %.*s", v.len, v.ptr);
  else if (macL != sizeof(new->mac))
    FNERR("need %u byte %s: %.*s", sizeof(new->mac), "mac", v.len, v.ptr);
  else if (key && keyL != sizeof(*new->mi_key))
    FNERR("need %u byte %s: %.*s", sizeof(*new->mi_key), "mi_key", v.len,
          v.ptr);
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

void atc_mi_sensors_init() {
  SLIST_INIT(&atc_mis);
}
