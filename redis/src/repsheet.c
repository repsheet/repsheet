/*
 * Repsheet module for Valkey and Redis.
 *
 * Stores reputation decisions (allow / block / mark) for actors and keeps an
 * ordered change log so enforcement points (the nginx module) can hold a
 * complete local copy and stay in sync without querying on every request.
 *
 * Keyspace (all keys share the {repsheet} hash tag so they live in one slot):
 *
 *   {repsheet}:actor:<actor>   hash   status, reason, created, expires, by
 *   {repsheet}:index           set    every actor that has a decision
 *   {repsheet}:meta            hash   epoch, seq
 *   {repsheet}:changes         stream change log, entry ID "<seq>-0"
 *   {repsheet}:notify          pubsub "<epoch>:<seq>" after each change
 *
 * `epoch` is a random id created with the dataset. If the dataset is flushed
 * or replaced, the epoch changes and consumers know to take a new snapshot.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "redismodule.h"
#include "repsheet_actor.h"

#define REPSHEET_VERSION "6.0.0"
#define REPSHEET_VERSION_NUM 60000

#define KEY_PREFIX "{repsheet}:actor:"
#define KEY_INDEX "{repsheet}:index"
#define KEY_META "{repsheet}:meta"
#define KEY_CHANGES "{repsheet}:changes"
#define CHANNEL_NOTIFY "{repsheet}:notify"

#define EPOCH_LEN 16
#define DEFAULT_CHANGELOG_MAX 100000
#define DEFAULT_CHANGES_COUNT 1000
#define MAX_CHANGES_COUNT 10000
#define MAX_TTL 315360000LL /* ten years */
#define MAX_BY 256

static long long changelog_max = DEFAULT_CHANGELOG_MAX;

/* ------------------------------------------------------------------------ */
/* helpers                                                                   */
/* ------------------------------------------------------------------------ */

static bool arg_is(RedisModuleString* arg, const char* name) {
  size_t len;
  const char* s = RedisModule_StringPtrLen(arg, &len);
  return len == strlen(name) && strncasecmp(s, name, len) == 0;
}

/* Canonicalize argv actor into `out`. Replies with an error on failure. */
static bool parse_actor(RedisModuleCtx* ctx, RedisModuleString* arg, char* out, rs_ip_t* ip) {
  size_t len;
  const char* s = RedisModule_StringPtrLen(arg, &len);
  const char* err = NULL;
  if (rs_actor_canonicalize(s, len, out, RS_ACTOR_MAX + 1, ip, &err) == 0) {
    RedisModule_ReplyWithErrorFormat(ctx, "ERR invalid actor: %s", err);
    return false;
  }
  return true;
}

/* Validate a BY value: at most MAX_BY bytes, no control characters. */
static bool parse_by(RedisModuleCtx* ctx, RedisModuleString* arg) {
  size_t len;
  const unsigned char* s = (const unsigned char*)RedisModule_StringPtrLen(arg, &len);
  if (len > MAX_BY) {
    RedisModule_ReplyWithErrorFormat(ctx, "ERR BY exceeds %d bytes", MAX_BY);
    return false;
  }
  for (size_t i = 0; i < len; i++) {
    if (s[i] < 0x20 || s[i] == 0x7f) {
      RedisModule_ReplyWithError(ctx, "ERR BY contains control characters");
      return false;
    }
  }
  return true;
}

static RedisModuleString* actor_key(RedisModuleCtx* ctx, const char* actor) {
  return RedisModule_CreateStringPrintf(ctx, KEY_PREFIX "%s", actor);
}

static long long reply_integer(RedisModuleCallReply* reply) {
  if (reply == NULL || RedisModule_CallReplyType(reply) != REDISMODULE_REPLY_INTEGER) return -1;
  return RedisModule_CallReplyInteger(reply);
}

/* Read a field from a hash key opened for reading. Returns NULL if missing. */
static RedisModuleString* hash_get(RedisModuleKey* key, const char* field) {
  RedisModuleString* value = NULL;
  /* Opening a missing key for reading yields NULL. */
  if (key == NULL || RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_HASH) return NULL;
  RedisModule_HashGet(key, REDISMODULE_HASH_CFIELDS, field, &value, NULL);
  return value;
}

static long long string_ll(RedisModuleString* s, long long fallback) {
  long long v;
  if (s == NULL || RedisModule_StringToLongLong(s, &v) != REDISMODULE_OK) return fallback;
  return v;
}

/* Current epoch, creating one if the dataset is new. `epoch` is EPOCH_LEN+1. */
static void ensure_epoch(RedisModuleCtx* ctx, char* epoch, bool create) {
  RedisModuleKey* meta =
      RedisModule_OpenKey(ctx, RedisModule_CreateString(ctx, KEY_META, strlen(KEY_META)), REDISMODULE_READ);
  RedisModuleString* value = hash_get(meta, "epoch");
  RedisModule_CloseKey(meta);

  if (value != NULL) {
    size_t len;
    const char* s = RedisModule_StringPtrLen(value, &len);
    snprintf(epoch, EPOCH_LEN + 1, "%.*s", (int)len, s);
    return;
  }

  if (!create) {
    epoch[0] = '\0';
    return;
  }

  RedisModule_GetRandomHexChars(epoch, EPOCH_LEN);
  epoch[EPOCH_LEN] = '\0';
  RedisModule_Call(ctx, "HSET", "!ccc", KEY_META, "epoch", epoch);
}

static long long current_seq(RedisModuleCtx* ctx) {
  RedisModuleKey* meta =
      RedisModule_OpenKey(ctx, RedisModule_CreateString(ctx, KEY_META, strlen(KEY_META)), REDISMODULE_READ);
  long long seq = string_ll(hash_get(meta, "seq"), 0);
  RedisModule_CloseKey(meta);
  return seq;
}

/* Append a change to the log and wake up subscribers. */
static void record_change(RedisModuleCtx* ctx, const char* op, const char* actor, const char* status,
                          RedisModuleString* reason, long long expires, RedisModuleString* by) {
  char epoch[EPOCH_LEN + 1];
  ensure_epoch(ctx, epoch, true);

  long long seq = reply_integer(RedisModule_Call(ctx, "HINCRBY", "!ccl", KEY_META, "seq", 1LL));

  char id[32];
  snprintf(id, sizeof(id), "%lld-0", seq);
  RedisModuleString* empty = RedisModule_CreateString(ctx, "", 0);
  RedisModule_Call(ctx, "XADD", "!cclccccccccsclcscl", KEY_CHANGES, "MAXLEN", changelog_max, id, "op", op,
                   "actor", actor, "status", status, "reason", reason ? reason : empty, "expires", expires, "by",
                   by ? by : empty, "at", RedisModule_Milliseconds());

  RedisModuleString* message = RedisModule_CreateStringPrintf(ctx, "%s:%lld", epoch, seq);
  RedisModule_Call(ctx, "PUBLISH", "cs", CHANNEL_NOTIFY, message);
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.ALLOW | BLOCK | MARK <actor> [REASON t] [TTL seconds] [BY who]  */
/* ------------------------------------------------------------------------ */

static int set_decision(RedisModuleCtx* ctx, RedisModuleString** argv, int argc, rs_status_t status) {
  if (argc < 2 || argc % 2 != 0) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char actor[RS_ACTOR_MAX + 1];
  if (!parse_actor(ctx, argv[1], actor, NULL)) return REDISMODULE_OK;

  RedisModuleString* reason = RedisModule_CreateString(ctx, "", 0);
  RedisModuleString* by = RedisModule_CreateString(ctx, "", 0);
  long long ttl = 0;

  for (int i = 2; i < argc; i += 2) {
    if (arg_is(argv[i], "REASON")) {
      size_t len;
      RedisModule_StringPtrLen(argv[i + 1], &len);
      if (len > RS_REASON_MAX) {
        return RedisModule_ReplyWithErrorFormat(ctx, "ERR reason exceeds %d bytes", RS_REASON_MAX);
      }
      reason = argv[i + 1];
    } else if (arg_is(argv[i], "TTL")) {
      if (RedisModule_StringToLongLong(argv[i + 1], &ttl) != REDISMODULE_OK || ttl <= 0 || ttl > MAX_TTL) {
        return RedisModule_ReplyWithError(ctx, "ERR TTL must be between 1 and 315360000 seconds");
      }
    } else if (arg_is(argv[i], "BY")) {
      if (!parse_by(ctx, argv[i + 1])) return REDISMODULE_OK;
      by = argv[i + 1];
    } else {
      return RedisModule_ReplyWithError(ctx, "ERR syntax error, expected REASON, TTL or BY");
    }
  }

  long long now = RedisModule_Milliseconds();
  long long expires = ttl > 0 ? now + ttl * 1000 : 0;
  const char* status_name = rs_status_name(status);
  RedisModuleString* key = actor_key(ctx, actor);

  RedisModule_Call(ctx, "DEL", "!s", key);
  RedisModule_Call(ctx, "HSET", "!scccsclclcs", key, "status", status_name, "reason", reason, "created", now,
                   "expires", expires, "by", by);
  if (expires > 0) RedisModule_Call(ctx, "PEXPIREAT", "!sl", key, expires);
  RedisModule_Call(ctx, "SADD", "!cc", KEY_INDEX, actor);

  record_change(ctx, "set", actor, status_name, reason, expires, by);
  return RedisModule_ReplyWithSimpleString(ctx, "OK");
}

static int AllowCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  return set_decision(ctx, argv, argc, RS_STATUS_ALLOW);
}

static int BlockCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  return set_decision(ctx, argv, argc, RS_STATUS_BLOCK);
}

static int MarkCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  return set_decision(ctx, argv, argc, RS_STATUS_MARK);
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.CLEAR <actor> [BY who]                                           */
/* ------------------------------------------------------------------------ */

static int ClearCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  if (argc != 2 && argc != 4) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char actor[RS_ACTOR_MAX + 1];
  if (!parse_actor(ctx, argv[1], actor, NULL)) return REDISMODULE_OK;

  RedisModuleString* by = NULL;
  if (argc == 4) {
    if (!arg_is(argv[2], "BY")) return RedisModule_ReplyWithError(ctx, "ERR syntax error, expected BY");
    if (!parse_by(ctx, argv[3])) return REDISMODULE_OK;
    by = argv[3];
  }

  long long deleted = reply_integer(RedisModule_Call(ctx, "DEL", "!s", actor_key(ctx, actor)));
  RedisModule_Call(ctx, "SREM", "!cc", KEY_INDEX, actor);

  if (deleted > 0) record_change(ctx, "del", actor, "none", NULL, 0, by);
  return RedisModule_ReplyWithLongLong(ctx, deleted > 0 ? 1 : 0);
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.GET <actor>                                                      */
/* ------------------------------------------------------------------------ */

typedef struct {
  rs_status_t status;
  RedisModuleString* reason;
  RedisModuleString* by;
  long long created;
  long long expires;
} decision_t;

static bool load_decision(RedisModuleCtx* ctx, const char* actor, decision_t* d) {
  RedisModuleKey* key = RedisModule_OpenKey(ctx, actor_key(ctx, actor), REDISMODULE_READ);
  if (RedisModule_KeyType(key) != REDISMODULE_KEYTYPE_HASH) {
    RedisModule_CloseKey(key);
    return false;
  }

  RedisModuleString *status = NULL, *created = NULL, *expires = NULL;
  d->reason = NULL;
  d->by = NULL;
  RedisModule_HashGet(key, REDISMODULE_HASH_CFIELDS, "status", &status, "reason", &d->reason, "created",
                      &created, "expires", &expires, "by", &d->by, NULL);
  RedisModule_CloseKey(key);

  size_t len;
  const char* s = status ? RedisModule_StringPtrLen(status, &len) : NULL;
  if (s == NULL || rs_status_parse(s, len, &d->status) != 0) return false;

  d->created = string_ll(created, 0);
  d->expires = string_ll(expires, 0);
  if (d->expires > 0 && d->expires <= RedisModule_Milliseconds()) return false;
  if (d->reason == NULL) d->reason = RedisModule_CreateString(ctx, "", 0);
  if (d->by == NULL) d->by = RedisModule_CreateString(ctx, "", 0);
  return true;
}

static int GetCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  if (argc != 2) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char actor[RS_ACTOR_MAX + 1];
  if (!parse_actor(ctx, argv[1], actor, NULL)) return REDISMODULE_OK;

  decision_t d;
  if (!load_decision(ctx, actor, &d)) return RedisModule_ReplyWithNull(ctx);

  RedisModule_ReplyWithMap(ctx, 6);
  RedisModule_ReplyWithSimpleString(ctx, "actor");
  RedisModule_ReplyWithCString(ctx, actor);
  RedisModule_ReplyWithSimpleString(ctx, "status");
  RedisModule_ReplyWithCString(ctx, rs_status_name(d.status));
  RedisModule_ReplyWithSimpleString(ctx, "reason");
  RedisModule_ReplyWithString(ctx, d.reason);
  RedisModule_ReplyWithSimpleString(ctx, "created");
  RedisModule_ReplyWithLongLong(ctx, d.created);
  RedisModule_ReplyWithSimpleString(ctx, "expires");
  RedisModule_ReplyWithLongLong(ctx, d.expires);
  RedisModule_ReplyWithSimpleString(ctx, "by");
  RedisModule_ReplyWithString(ctx, d.by);
  return REDISMODULE_OK;
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.CHECK <actor> [<actor> ...]                                      */
/*                                                                           */
/* Evaluate the decision for a request made by the given actors, exactly as  */
/* the nginx module does: an IP matches itself and every network containing */
/* it; allow beats block beats mark; the most specific match wins a tie.     */
/* Replies [status, reason, matched-actor].                                  */
/* ------------------------------------------------------------------------ */

typedef struct {
  rs_status_t status;
  RedisModuleString* reason;
  char actor[RS_ACTOR_MAX + 1];
} verdict_t;

static void consider(RedisModuleCtx* ctx, verdict_t* v, const char* actor) {
  decision_t d;
  if (!load_decision(ctx, actor, &d)) return;
  if (d.status > v->status) {
    v->status = d.status;
    v->reason = d.reason;
    snprintf(v->actor, sizeof(v->actor), "%s", actor);
  }
}

static int CheckCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  if (argc < 2) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  verdict_t v = {.status = RS_STATUS_NONE, .reason = NULL};

  for (int i = 1; i < argc; i++) {
    char actor[RS_ACTOR_MAX + 1];
    rs_ip_t ip;
    if (!parse_actor(ctx, argv[i], actor, &ip)) return REDISMODULE_OK;

    if (ip.family == 0) {
      consider(ctx, &v, actor);
      continue;
    }

    for (int prefix = ip.prefix; prefix >= 0; prefix--) {
      rs_ip_t net = ip;
      rs_ip_mask(&net, (uint8_t)prefix);
      memcpy(actor, "ip:", 3);
      if (rs_ip_format(&net, actor + 3, sizeof(actor) - 3) == 0) continue;
      consider(ctx, &v, actor);
    }
  }

  RedisModule_ReplyWithArray(ctx, 3);
  RedisModule_ReplyWithSimpleString(ctx, rs_status_name(v.status));
  if (v.status == RS_STATUS_NONE) {
    RedisModule_ReplyWithNull(ctx);
    RedisModule_ReplyWithNull(ctx);
  } else {
    RedisModule_ReplyWithString(ctx, v.reason);
    RedisModule_ReplyWithCString(ctx, v.actor);
  }
  return REDISMODULE_OK;
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.SNAPSHOT                                                         */
/*                                                                           */
/* Replies [epoch, seq, [[actor, status, reason, expires], ...]] atomically. */
/* Read-only, so enforcement points may sync from a replica.               */
/* ------------------------------------------------------------------------ */

static int SnapshotCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  if (argc != 1) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  char epoch[EPOCH_LEN + 1];
  ensure_epoch(ctx, epoch, false);

  RedisModule_ReplyWithArray(ctx, 3);
  RedisModule_ReplyWithCString(ctx, epoch);
  RedisModule_ReplyWithLongLong(ctx, current_seq(ctx));
  RedisModule_ReplyWithArray(ctx, REDISMODULE_POSTPONED_LEN);

  RedisModuleCallReply* members = RedisModule_Call(ctx, "SMEMBERS", "c", KEY_INDEX);
  size_t n = RedisModule_CallReplyLength(members);
  long emitted = 0;

  for (size_t i = 0; i < n; i++) {
    size_t len;
    const char* s = RedisModule_CallReplyStringPtr(RedisModule_CallReplyArrayElement(members, i), &len);
    char actor[RS_ACTOR_MAX + 1];
    if (len > RS_ACTOR_MAX) continue;
    memcpy(actor, s, len);
    actor[len] = '\0';

    decision_t d;
    if (!load_decision(ctx, actor, &d)) continue;

    RedisModule_ReplyWithArray(ctx, 4);
    RedisModule_ReplyWithCString(ctx, actor);
    RedisModule_ReplyWithCString(ctx, rs_status_name(d.status));
    RedisModule_ReplyWithString(ctx, d.reason);
    RedisModule_ReplyWithLongLong(ctx, d.expires);
    emitted++;
  }

  RedisModule_ReplySetArrayLength(ctx, emitted);
  return REDISMODULE_OK;
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.CHANGES <epoch> <seq> [COUNT n]                                  */
/*                                                                           */
/* Replies ["OK", epoch, seq, [[seq, op, actor, status, reason, expires]..]] */
/* with changes after <seq>, or ["RESYNC"] if the caller must take a new     */
/* snapshot (different epoch, or the log was trimmed past <seq>).            */
/*                                                                           */
/* A caller that synced an empty dataset (epoch "", seq 0) can follow the    */
/* log from the first write without a new snapshot, as long as the log is    */
/* still complete; it adopts the epoch returned here.                        */
/* ------------------------------------------------------------------------ */

static int reply_resync(RedisModuleCtx* ctx) {
  RedisModule_ReplyWithArray(ctx, 1);
  return RedisModule_ReplyWithSimpleString(ctx, "RESYNC");
}

static long long entry_seq(RedisModuleCallReply* entry) {
  size_t len;
  const char* id = RedisModule_CallReplyStringPtr(RedisModule_CallReplyArrayElement(entry, 0), &len);
  return id ? strtoll(id, NULL, 10) : -1;
}

static RedisModuleCallReply* entry_field(RedisModuleCallReply* entry, const char* name) {
  RedisModuleCallReply* fields = RedisModule_CallReplyArrayElement(entry, 1);
  size_t n = RedisModule_CallReplyLength(fields);
  for (size_t i = 0; i + 1 < n; i += 2) {
    size_t len;
    const char* f = RedisModule_CallReplyStringPtr(RedisModule_CallReplyArrayElement(fields, i), &len);
    if (f && len == strlen(name) && memcmp(f, name, len) == 0) {
      return RedisModule_CallReplyArrayElement(fields, i + 1);
    }
  }
  return NULL;
}

static void reply_field(RedisModuleCtx* ctx, RedisModuleCallReply* entry, const char* name) {
  RedisModuleCallReply* value = entry_field(entry, name);
  if (value == NULL) {
    RedisModule_ReplyWithCString(ctx, "");
  } else {
    RedisModule_ReplyWithCallReply(ctx, value);
  }
}

static int ChangesCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  if (argc != 3 && argc != 5) return RedisModule_WrongArity(ctx);
  RedisModule_AutoMemory(ctx);

  long long since, count = DEFAULT_CHANGES_COUNT;
  if (RedisModule_StringToLongLong(argv[2], &since) != REDISMODULE_OK || since < 0) {
    return RedisModule_ReplyWithError(ctx, "ERR seq must be a non-negative integer");
  }
  if (argc == 5) {
    if (!arg_is(argv[3], "COUNT") || RedisModule_StringToLongLong(argv[4], &count) != REDISMODULE_OK ||
        count <= 0 || count > MAX_CHANGES_COUNT) {
      return RedisModule_ReplyWithError(ctx, "ERR COUNT must be between 1 and 10000");
    }
  }

  char epoch[EPOCH_LEN + 1];
  ensure_epoch(ctx, epoch, false);
  size_t elen;
  const char* client_epoch = RedisModule_StringPtrLen(argv[1], &elen);
  bool from_empty = elen == 0 && since == 0;
  if (!from_empty && (elen != strlen(epoch) || memcmp(client_epoch, epoch, elen) != 0)) {
    return reply_resync(ctx);
  }

  long long seq = current_seq(ctx);
  if (since > seq) return reply_resync(ctx);

  if (since < seq) {
    /* The log must still hold the entry right after `since`. */
    RedisModuleCallReply* first =
        RedisModule_Call(ctx, "XRANGE", "ccccl", KEY_CHANGES, "-", "+", "COUNT", 1LL);
    if (RedisModule_CallReplyLength(first) == 0) return reply_resync(ctx);
    if (entry_seq(RedisModule_CallReplyArrayElement(first, 0)) > since + 1) return reply_resync(ctx);
  }

  char start[32];
  snprintf(start, sizeof(start), "%lld-0", since + 1);
  RedisModuleCallReply* entries =
      since < seq ? RedisModule_Call(ctx, "XRANGE", "ccccl", KEY_CHANGES, start, "+", "COUNT", count) : NULL;
  size_t n = entries ? RedisModule_CallReplyLength(entries) : 0;
  long long cursor = since;

  RedisModule_ReplyWithArray(ctx, 4);
  RedisModule_ReplyWithSimpleString(ctx, "OK");
  RedisModule_ReplyWithCString(ctx, epoch);
  if (n > 0) cursor = entry_seq(RedisModule_CallReplyArrayElement(entries, n - 1));
  RedisModule_ReplyWithLongLong(ctx, cursor);
  RedisModule_ReplyWithArray(ctx, (long)n);

  for (size_t i = 0; i < n; i++) {
    RedisModuleCallReply* entry = RedisModule_CallReplyArrayElement(entries, i);
    RedisModule_ReplyWithArray(ctx, 6);
    RedisModule_ReplyWithLongLong(ctx, entry_seq(entry));
    reply_field(ctx, entry, "op");
    reply_field(ctx, entry, "actor");
    reply_field(ctx, entry, "status");
    reply_field(ctx, entry, "reason");
    reply_field(ctx, entry, "expires");
  }
  return REDISMODULE_OK;
}

/* ------------------------------------------------------------------------ */
/* REPSHEET.VERSION                                                          */
/* ------------------------------------------------------------------------ */

static int VersionCommand(RedisModuleCtx* ctx, RedisModuleString** argv, int argc) {
  if (argc != 1) return RedisModule_WrongArity(ctx);
  return RedisModule_ReplyWithSimpleString(ctx, REPSHEET_VERSION);
}

/* ------------------------------------------------------------------------ */
/* Expiry: drop expired actors from the index.                               */
/* ------------------------------------------------------------------------ */

static void free_string(void* p) {
  RedisModule_Free(p);
}

static void remove_from_index(RedisModuleCtx* ctx, void* actor) {
  RedisModule_Call(ctx, "SREM", "!cc", KEY_INDEX, (const char*)actor);
}

static int on_expired(RedisModuleCtx* ctx, int type, const char* event, RedisModuleString* key) {
  if (RedisModule_GetContextFlags(ctx) & REDISMODULE_CTX_FLAGS_SLAVE) return REDISMODULE_OK;

  size_t len;
  const char* k = RedisModule_StringPtrLen(key, &len);
  size_t plen = strlen(KEY_PREFIX);
  if (len <= plen || memcmp(k, KEY_PREFIX, plen) != 0) return REDISMODULE_OK;

  char* actor = RedisModule_Alloc(len - plen + 1);
  memcpy(actor, k + plen, len - plen);
  actor[len - plen] = '\0';
  if (RedisModule_AddPostNotificationJob(ctx, remove_from_index, actor, free_string) != REDISMODULE_OK) {
    RedisModule_Free(actor);
  }
  return REDISMODULE_OK;
}

/* ------------------------------------------------------------------------ */
/* Module registration                                                       */
/* ------------------------------------------------------------------------ */

typedef struct {
  const char* name;
  RedisModuleCmdFunc fn;
  const char* flags;
} command_t;

static const command_t commands[] = {
    {"repsheet.allow", AllowCommand, "write deny-oom"},    {"repsheet.block", BlockCommand, "write deny-oom"},
    {"repsheet.mark", MarkCommand, "write deny-oom"},      {"repsheet.clear", ClearCommand, "write"},
    {"repsheet.get", GetCommand, "readonly fast"},         {"repsheet.check", CheckCommand, "readonly"},
    {"repsheet.snapshot", SnapshotCommand, "readonly"},    {"repsheet.changes", ChangesCommand, "readonly"},
    {"repsheet.version", VersionCommand, "readonly fast"},
};

__attribute__((visibility("default"))) int RedisModule_OnLoad(RedisModuleCtx* ctx, RedisModuleString** argv,
                                                              int argc) {
  if (RedisModule_Init(ctx, "repsheet", REPSHEET_VERSION_NUM, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
    return REDISMODULE_ERR;
  }

  if (!RMAPI_FUNC_SUPPORTED(RedisModule_AddPostNotificationJob) ||
      !RMAPI_FUNC_SUPPORTED(RedisModule_ReplyWithErrorFormat)) {
    RedisModule_Log(ctx, "warning", "repsheet requires Valkey >= 7.2 or Redis >= 7.2");
    return REDISMODULE_ERR;
  }

  for (int i = 0; i < argc; i += 2) {
    if (i + 1 < argc && arg_is(argv[i], "changelog-max")) {
      if (RedisModule_StringToLongLong(argv[i + 1], &changelog_max) != REDISMODULE_OK || changelog_max < 1) {
        RedisModule_Log(ctx, "warning", "repsheet: changelog-max must be a positive integer");
        return REDISMODULE_ERR;
      }
    } else {
      RedisModule_Log(ctx, "warning", "repsheet: unknown module argument");
      return REDISMODULE_ERR;
    }
  }

  for (size_t i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
    if (RedisModule_CreateCommand(ctx, commands[i].name, commands[i].fn, commands[i].flags, 0, 0, 0) ==
        REDISMODULE_ERR) {
      return REDISMODULE_ERR;
    }
  }

  RedisModule_SubscribeToKeyspaceEvents(ctx, REDISMODULE_NOTIFY_EXPIRED, on_expired);
  return REDISMODULE_OK;
}
