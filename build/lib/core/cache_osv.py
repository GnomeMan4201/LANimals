import os, json

CACHE_FILE = "osv_cache.json"
cache = {}

if os.path.exists(CACHE_FILE):
    with open(CACHE_FILE) as f:
        try:
            cache = json.load(f)
        except Exception:
            cache = {}

def cached_query_osv(package_name, ecosystem, query_fn):
    key = f"{ecosystem}:{package_name}"
    if key in cache:
        return cache[key]
    result = query_fn(package_name, ecosystem)
    cache[key] = result
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)
    return result
