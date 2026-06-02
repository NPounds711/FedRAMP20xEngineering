# fixture collector — returns a normalized in-memory payload
def collect(config):
    return {
        "enabled": config.get("enabled", True),
        "resource_id": config.get("resource_id", "fixture-1"),
    }
