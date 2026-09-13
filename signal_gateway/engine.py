import html
import json
import re
from collections.abc import Mapping

TOKEN = re.compile(r"\{\{\s*([^{}]+?)\s*\}\}")


def flatten(value, prefix=""):
    """Return every leaf as a dotted/indexed path; containers remain addressable."""
    out = {}
    if prefix:
        out[prefix] = value
    if isinstance(value, Mapping):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            out.update(flatten(child, path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            path = f"{prefix}.{index}" if prefix else str(index)
            out.update(flatten(child, path))
    return out


def _values(variables, path):
    if "*" not in path:
        return [variables[path]] if path in variables else []
    pattern = re.compile("^" + re.escape(path).replace(r"\*", r"[^.]+") + "$")
    return [value for key, value in variables.items() if pattern.match(key)]


def match_condition(condition, variables):
    values = _values(variables, condition.get("path", ""))
    op, wanted = condition.get("operator", "equals"), condition.get("value")
    if op == "exists":
        return bool(values)
    if op == "not_exists":
        return not values

    def compare(actual):
        if op == "equals": return actual == wanted or str(actual) == str(wanted)
        if op == "not_equals": return not (actual == wanted or str(actual) == str(wanted))
        if op == "contains": return str(wanted) in str(actual)
        if op == "starts_with": return str(actual).startswith(str(wanted))
        if op == "ends_with": return str(actual).endswith(str(wanted))
        if op == "regex":
            try: return re.search(str(wanted), str(actual)) is not None
            except re.error: return False
        if op in {"gt", "gte", "lt", "lte"}:
            try: left, right = float(actual), float(wanted)
            except (TypeError, ValueError): return False
            return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[op]
        if op == "in":
            choices = wanted if isinstance(wanted, list) else [x.strip() for x in str(wanted).split(",")]
            return actual in choices or str(actual) in {str(x) for x in choices}
        return False

    return any(compare(value) for value in values)


def rule_matches(rule, variables):
    conditions = rule.get("conditions", [])
    results = [match_condition(item, variables) for item in conditions]
    return all(results) if rule.get("match_mode", "all") == "all" else any(results)


def render(template, variables, allow_html=False):
    def replace(match):
        key = match.group(1).strip()
        value = variables.get(key, "")
        if isinstance(value, (dict, list)):
            value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
        value = str(value)
        # Static template markup may be retained, but payload-derived values are
        # always escaped so an incoming webhook cannot inject Pushover HTML.
        return html.escape(value)
    return TOKEN.sub(replace, template)


def evaluate(payload, rules):
    variables = flatten(payload)
    outputs = []
    for rule in sorted((r for r in rules if r.get("enabled", True)), key=lambda r: r.get("priority", 100)):
        if rule_matches(rule, variables):
            outputs.append({
                "rule": rule.get("name", "Unnamed Rule"),
                "title": render(rule.get("title_template", "Signal Gateway"), variables),
                "message": render(rule.get("message_template", ""), variables, rule.get("html", True)),
                "html": bool(rule.get("html", True)),
                "priority": int(rule.get("pushover_priority", 0)),
                "sound": rule.get("sound", "pushover"),
            })
            if rule.get("stop_processing"):
                break
    return variables, outputs
