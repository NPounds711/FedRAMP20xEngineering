import json


def render(determinations) -> str:
    return json.dumps({"determinations": list(determinations)}, indent=2, sort_keys=True)
