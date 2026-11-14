# Repsheet Redis Module

## Module Commands

* `REPSHEET.BLACKLIST` - Blacklist an IP Address
* `REPSHEET.WHITELIST` - Whitelist an IP Address
* `REPSHEET.MARK`      - Mark an IP Address
* `REPSHEET.STATUS`    - Get the Status of an IP Address
* `REPSHEET.VERSION`   - Get the Current Version

## Quick Start Guide

1. Build the module by running `make`
2. Run redis loading the module: `/path/to/redis-server --loadmodule ./repsheet.so`

Now run `redis-cli` and try the commands:

```
127.0.0.1:6379> REPSHEET.BLACKLIST 1.1.1.1 manual
OK
127.0.0.1:6379> keys *
1) "1.1.1.1:repsheet:ip:blacklisted"
127.0.0.1:6379> get 1.1.1.1:repsheet:ip:blacklisted
"manual"
127.0.0.1:6379> REPSHEET.STATUS 1.1.1.1
BLACKLISTED
```
