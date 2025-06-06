def parse_requirements(path):
    with open(path) as f:
        return [line.strip().split("==")[0] for line in f if line.strip() and not line.startswith("#")]

def parse_package_lock(path):
    import json
    with open(path) as f:
        data = json.load(f)
    return list(data.get("dependencies", {}).keys())
