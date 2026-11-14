#include "repsheet_actor.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static const char* status_names[] = {"none", "mark", "block", "allow"};

const char* rs_status_name(rs_status_t status) {
  if (status > RS_STATUS_ALLOW) return "none";
  return status_names[status];
}

int rs_status_parse(const char* s, size_t len, rs_status_t* out) {
  for (int i = RS_STATUS_MARK; i <= RS_STATUS_ALLOW; i++) {
    if (strlen(status_names[i]) == len && memcmp(status_names[i], s, len) == 0) {
      *out = (rs_status_t)i;
      return 0;
    }
  }
  return -1;
}

void rs_ip_mask(rs_ip_t* ip, uint8_t prefix) {
  size_t bytes = ip->family == 4 ? 4 : 16;
  ip->prefix = prefix;
  for (size_t i = 0; i < bytes; i++) {
    size_t bit = i * 8;
    if (bit >= prefix) {
      ip->addr[i] = 0;
    } else if (bit + 8 > prefix) {
      ip->addr[i] &= (uint8_t)(0xff << (8 - (prefix - bit)));
    }
  }
  for (size_t i = bytes; i < 16; i++) ip->addr[i] = 0;
}

static const uint8_t v4mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};

void rs_ip_from_bytes(rs_ip_t* ip, int family, const uint8_t* bytes) {
  memset(ip, 0, sizeof(*ip));
  if (family == 6 && memcmp(bytes, v4mapped, sizeof(v4mapped)) == 0) {
    ip->family = 4;
    ip->prefix = 32;
    memcpy(ip->addr, bytes + 12, 4);
    return;
  }
  ip->family = (uint8_t)family;
  ip->prefix = family == 4 ? 32 : 128;
  memcpy(ip->addr, bytes, family == 4 ? 4 : 16);
}

int rs_ip_parse(const char* s, size_t len, rs_ip_t* ip) {
  char buf[INET6_ADDRSTRLEN + 5];
  if (len == 0 || len >= sizeof(buf)) return -1;
  memcpy(buf, s, len);
  buf[len] = '\0';

  int prefix = -1;
  char* slash = strchr(buf, '/');
  if (slash != NULL) {
    *slash = '\0';
    const char* p = slash + 1;
    if (*p == '\0' || strlen(p) > 3) return -1;
    prefix = 0;
    for (; *p; p++) {
      if (*p < '0' || *p > '9') return -1;
      prefix = prefix * 10 + (*p - '0');
    }
  }

  uint8_t raw[16];
  int family;
  if (inet_pton(AF_INET, buf, raw) == 1) {
    family = 4;
  } else if (inet_pton(AF_INET6, buf, raw) == 1) {
    family = 6;
  } else {
    return -1;
  }

  int max = family == 4 ? 32 : 128;
  if (prefix > max) return -1;

  rs_ip_from_bytes(ip, family, raw);
  if (prefix >= 0) {
    /* An IPv4-mapped network keeps its meaning: ::ffff:10.0.0.0/104 == 10.0.0.0/8 */
    if (family == 6 && ip->family == 4) {
      if (prefix < 96) return -1;
      prefix -= 96;
    }
    rs_ip_mask(ip, (uint8_t)prefix);
  }
  return 0;
}

size_t rs_ip_format(const rs_ip_t* ip, char* out, size_t outlen) {
  char addr[INET6_ADDRSTRLEN];
  if (inet_ntop(ip->family == 4 ? AF_INET : AF_INET6, ip->addr, addr, sizeof(addr)) == NULL) {
    return 0;
  }
  int full = ip->family == 4 ? 32 : 128;
  int n = ip->prefix == full ? snprintf(out, outlen, "%s", addr)
                             : snprintf(out, outlen, "%s/%u", addr, ip->prefix);
  if (n < 0 || (size_t)n >= outlen) return 0;
  return (size_t)n;
}

size_t rs_ip_key(const rs_ip_t* ip, uint8_t* out) {
  size_t bytes = ip->family == 4 ? 4 : 16;
  out[0] = 'I';
  out[1] = ip->family;
  out[2] = ip->prefix;
  memcpy(out + 3, ip->addr, bytes);
  return 3 + bytes;
}

static int valid_type_char(char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-';
}

size_t rs_actor_canonicalize(const char* in, size_t len, char* out, size_t outlen, rs_ip_t* ip,
                             const char** err) {
  rs_ip_t local;
  if (ip == NULL) ip = &local;
  memset(ip, 0, sizeof(*ip));

  /* Bare address or network. */
  if (rs_ip_parse(in, len, ip) == 0) goto format_ip;

  const char* colon = memchr(in, ':', len);
  if (colon == NULL || colon == in) {
    *err = "actor must be an IP address, a network, or <type>:<value>";
    return 0;
  }

  size_t tlen = (size_t)(colon - in);
  const char* value = colon + 1;
  size_t vlen = len - tlen - 1;
  char type[RS_TYPE_MAX + 1];

  /* Something shaped like IPv6 ("2001:db8::/129") is a bad address, not a type. */
  if (tlen <= 4 && memchr(value, ':', vlen) != NULL) {
    bool hex = true;
    for (size_t i = 0; i < tlen && hex; i++) hex = isxdigit((unsigned char)in[i]) != 0;
    if (hex) {
      *err = "invalid IP address or network";
      return 0;
    }
  }

  if (tlen > RS_TYPE_MAX) {
    *err = "actor type is too long";
    return 0;
  }
  for (size_t i = 0; i < tlen; i++) {
    char c = in[i];
    if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    if (!valid_type_char(c)) {
      *err = "actor type may only contain [a-z0-9_-]";
      return 0;
    }
    type[i] = c;
  }
  type[tlen] = '\0';

  if (strcmp(type, "ip") == 0) {
    if (rs_ip_parse(value, vlen, ip) != 0) {
      *err = "invalid IP address or network";
      return 0;
    }
    goto format_ip;
  }

  if (vlen == 0) {
    *err = "actor value is empty";
    return 0;
  }
  for (size_t i = 0; i < vlen; i++) {
    unsigned char c = (unsigned char)value[i];
    if (c < 0x20 || c == 0x7f) {
      *err = "actor value contains control characters";
      return 0;
    }
  }
  if (tlen + 1 + vlen > RS_ACTOR_MAX || tlen + 1 + vlen + 1 > outlen) {
    *err = "actor is too long";
    return 0;
  }
  memcpy(out, type, tlen);
  out[tlen] = ':';
  memcpy(out + tlen + 1, value, vlen);
  out[tlen + 1 + vlen] = '\0';
  return tlen + 1 + vlen;

format_ip:
  if (outlen < 4) {
    *err = "output buffer too small";
    return 0;
  }
  memcpy(out, "ip:", 3);
  size_t n = rs_ip_format(ip, out + 3, outlen - 3);
  if (n == 0) {
    *err = "could not format address";
    return 0;
  }
  return n + 3;
}
