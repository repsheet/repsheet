#include <stdbool.h>
#include "../redismodule.h"
#include "../rmutil/util.h"
#include "../rmutil/strings.h"
#include "../rmutil/test_util.h"

#define VERSION "0.0.7"
#define MAX_REASON_LENGTH 1024

static char *str(RedisModuleString *input) {
  size_t len;
  const char *s = RedisModule_StringPtrLen(input, &len);
  char *p = RedisModule_Alloc(len + 1);
  memcpy(p, s, len);
  *(p + len) = 0;
  return p;
}

static void publish(RedisModuleCtx *ctx, RedisModuleString *actor, RedisModuleString *reason, const char *list) {
  RedisModuleString *channel = RedisModule_CreateStringPrintf(ctx, "repsheet:ip:%s", list);
  RedisModuleString *message = RedisModule_CreateStringPrintf(ctx, "%s,%s", str(actor), str(reason));
  RedisModuleCallReply *reply = RedisModule_Call(ctx, "PUBLISH", "ss", channel, message);
  if (RedisModule_CallReplyType(reply) == REDISMODULE_REPLY_ERROR) {
    RedisModule_Log(ctx, "error", "Could not send PUBLISH");
  }
}

int Record(RedisModuleCtx *ctx, RedisModuleString **argv, int argc, const char *list) {
  if (argc != 3 && argc != 4) {
    return RedisModule_WrongArity(ctx);
  }

  RedisModule_AutoMemory(ctx);

  RedisModuleString *keyString = RedisModule_CreateStringPrintf(ctx, "%s:repsheet:ip:%s", str(argv[1]), list);
  RedisModuleKey *key = RedisModule_OpenKey(ctx, keyString, REDISMODULE_READ | REDISMODULE_WRITE);

  int keyType = RedisModule_KeyType(key);
  if (keyType == REDISMODULE_KEYTYPE_EMPTY || keyType == REDISMODULE_KEYTYPE_STRING) {
    RedisModule_StringSet(key, argv[2]);
    if (argc == 4) {
      long long timeout;
      RedisModule_StringToLongLong(argv[3], &timeout);
      RedisModule_SetExpire(key, timeout * 1000);
    }
  }

  RedisModule_CloseKey(key);
  publish(ctx, argv[1], argv[2], list);
  RedisModule_ReplyWithSimpleString(ctx, "OK");

  return REDISMODULE_OK;
}

bool CheckList(RedisModuleCtx *ctx, RedisModuleString *list, char *value) {
  bool isListed = false;

  RedisModuleKey *key = RedisModule_OpenKey(ctx, list, REDISMODULE_READ);

  int keyType = RedisModule_KeyType(key);
  if (keyType == REDISMODULE_KEYTYPE_STRING) {
    isListed = true;
    size_t len = RedisModule_ValueLength(key);
    char *dma_value = RedisModule_StringDMA(key, &len, REDISMODULE_READ);
    strncpy(value, dma_value, len);
  }

  RedisModule_CloseKey(key);

  return isListed;
}

/*
 * REPSHEET.BLACKLIST <actor> <reason> <ttl>
 * Creates a Repsheet blacklist entry for the specified address.
 * If a ttl is provided, the key will be set to expire after <ttl>
 * seconds.
 *
 */
int BlacklistCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  return Record(ctx, argv, argc, "blacklisted");
}

/*
 * REPSHEET.WHITELIST <actor> <reason> <ttl>
 * Creates a Repsheet whitelist entry for the specified address.
 * If a ttl is provided, the key will be set to expire after <ttl>
 * seconds.
 *
 */
int WhitelistCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  return Record(ctx, argv, argc, "whitelisted");
}

/*
 * REPSHEET.MARK <actor> <reason> <ttl>
 * Creates a Repsheet marklist entry for the specified address.
 * If a ttl is provided, the key will be set to expire after <ttl>
 * seconds.
 *
 */
int MarkCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  return Record(ctx, argv, argc, "marked");
}


/*
 * REPSHEET.STATUS <actor>
 * Looks up the actor in the cache and returns its status
 *
 */
int StatusCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  if (argc != 2) {
    return RedisModule_WrongArity(ctx);
  }

  RedisModule_AutoMemory(ctx);

  RedisModuleString *whitelist = RedisModule_CreateStringPrintf(ctx, "%s:repsheet:ip:whitelisted", str(argv[1]));
  RedisModuleString *blacklist = RedisModule_CreateStringPrintf(ctx, "%s:repsheet:ip:blacklisted", str(argv[1]));
  RedisModuleString *marklist = RedisModule_CreateStringPrintf(ctx, "%s:repsheet:ip:marked", str(argv[1]));

  char reason[MAX_REASON_LENGTH] = {'\0'};

  bool isWhitelisted = CheckList(ctx, whitelist, reason);
  if (isWhitelisted) {
    RedisModule_ReplyWithArray(ctx, 2);
    RedisModule_ReplyWithSimpleString(ctx, "WHITELISTED");
    RedisModule_ReplyWithSimpleString(ctx, reason);
    return REDISMODULE_OK;
  }

  memset(reason, '\0', MAX_REASON_LENGTH);
  bool isBlacklisted = CheckList(ctx, blacklist, reason);
  if (isBlacklisted) {
    RedisModule_ReplyWithArray(ctx, 2);
    RedisModule_ReplyWithSimpleString(ctx, "BLACKLISTED");
    RedisModule_ReplyWithSimpleString(ctx, reason);
    return REDISMODULE_OK;
  }

  memset(reason, '\0', MAX_REASON_LENGTH);
  bool isMarked = CheckList(ctx, marklist, reason);
  if (isMarked) {
    RedisModule_ReplyWithArray(ctx, 2);
    RedisModule_ReplyWithSimpleString(ctx, "MARKED");
    RedisModule_ReplyWithSimpleString(ctx, reason);
    return REDISMODULE_OK;
  }

  RedisModule_ReplyWithArray(ctx, 2);
  RedisModule_ReplyWithSimpleString(ctx, "OK");
  RedisModule_ReplyWithSimpleString(ctx, "");
  return REDISMODULE_OK;
}

int VersionCommand(RedisModuleCtx *ctx, RedisModuleString **argv, int argc) {
  RedisModule_ReplyWithSimpleString(ctx, VERSION);
  return REDISMODULE_OK;
}

int RedisModule_OnLoad(RedisModuleCtx *ctx) {
  if (RedisModule_Init(ctx, "repsheet", 1, REDISMODULE_APIVER_1) == REDISMODULE_ERR) {
    return REDISMODULE_ERR;
  }

  RMUtil_RegisterWriteCmd(ctx, "repsheet.blacklist", BlacklistCommand);
  RMUtil_RegisterWriteCmd(ctx, "repsheet.whitelist", WhitelistCommand);
  RMUtil_RegisterWriteCmd(ctx, "repsheet.mark",      MarkCommand);
  RMUtil_RegisterWriteCmd(ctx, "repsheet.status",    StatusCommand);
  RMUtil_RegisterWriteCmd(ctx, "repsheet.version",   VersionCommand);

  return REDISMODULE_OK;
}
