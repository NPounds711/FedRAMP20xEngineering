import yaml


def render(determinations) -> str:
    return yaml.safe_dump({"determinations": list(determinations)}, sort_keys=True)
