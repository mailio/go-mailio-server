package global

import "time"

const REDIS_DID_CACHE_PREFIX = "cached_did:"
const REDIS_DID_CACHE_TTL = time.Hour * 24 * 7 // 1 week
