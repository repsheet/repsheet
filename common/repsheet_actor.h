/*
 * Repsheet actor and status handling shared by the Redis/Valkey module and
 * the nginx module. Dependency free C99.
 *
 * An actor is identified by a canonical string of the form "<type>:<value>".
 *
 *   ip:203.0.113.7          a single IPv4 address
 *   ip:203.0.113.0/24       an IPv4 network
 *   ip:2001:db8::/64        an IPv6 network
 *   session:9f2c...         any other actor type, e.g. a session cookie
 *
 * Addresses are canonicalized: host bits are masked off, IPv4-mapped IPv6
 * addresses become IPv4, and a full-length prefix (/32, /128) is omitted.
 */
#ifndef REPSHEET_ACTOR_H
#define REPSHEET_ACTOR_H

#include <stddef.h>
#include <stdint.h>

#define RS_ACTOR_MAX 512   /* max length of a canonical actor string */
#define RS_TYPE_MAX 32     /* max length of an actor type */
#define RS_REASON_MAX 1024 /* max length of a decision reason */
#define RS_IP_KEY_MAX 19   /* 'I' + family + prefix + 16 address bytes */

/* Higher value wins when several decisions apply to one request. */
typedef enum {
  RS_STATUS_NONE = 0,
  RS_STATUS_MARK = 1,
  RS_STATUS_BLOCK = 2,
  RS_STATUS_ALLOW = 3,
} rs_status_t;

typedef struct {
  uint8_t family; /* 4 or 6 */
  uint8_t prefix; /* 0-32 or 0-128 */
  uint8_t addr[16];
} rs_ip_t;

const char* rs_status_name(rs_status_t status);
int rs_status_parse(const char* s, size_t len, rs_status_t* out);

/*
 * Parse "addr" or "addr/prefix". Masks host bits and folds IPv4-mapped IPv6
 * into IPv4. Returns 0 on success, -1 if the input is not an address.
 */
int rs_ip_parse(const char* s, size_t len, rs_ip_t* ip);

/* Build an rs_ip_t for a full-length address from raw bytes. */
void rs_ip_from_bytes(rs_ip_t* ip, int family, const uint8_t* bytes);

/* Zero all bits past `prefix` and set ip->prefix. */
void rs_ip_mask(rs_ip_t* ip, uint8_t prefix);

/* Canonical text ("10.0.0.0/8", "2001:db8::1"). Returns length or 0. */
size_t rs_ip_format(const rs_ip_t* ip, char* out, size_t outlen);

/* Compact binary lookup key used by the nginx shared memory index. */
size_t rs_ip_key(const rs_ip_t* ip, uint8_t* out);

/*
 * Canonicalize user supplied actor text into "<type>:<value>".
 * A bare address or network is accepted as an "ip" actor. When the actor is
 * an IP actor and `ip` is not NULL, the parsed address is stored there and
 * ip->family is set; otherwise ip->family is 0.
 *
 * Returns the length written to `out` (NUL terminated), or 0 on error with
 * `*err` pointing at a static message.
 */
size_t rs_actor_canonicalize(const char* in, size_t len, char* out, size_t outlen, rs_ip_t* ip,
                             const char** err);

#endif
