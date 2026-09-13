from notifyrouter.engine import evaluate, flatten, render


PAYLOAD={"alarm_id":"a1","events":[{"alert_key":"CLIENT_CONNECTED","scope":{"site_id":"s1"}}]}


def test_flatten_exposes_every_leaf_and_container():
    values=flatten(PAYLOAD)
    assert values["alarm_id"]=="a1"
    assert values["events.0.alert_key"]=="CLIENT_CONNECTED"
    assert values["events.0.scope.site_id"]=="s1"


def test_wildcard_rule_and_template():
    rules=[{"name":"Connected","conditions":[{"path":"events.*.alert_key","operator":"equals","value":"CLIENT_CONNECTED"}],"title_template":"Event {{ events.0.alert_key }}","message_template":"Site <b>{{ events.0.scope.site_id }}</b>","html":True}]
    variables,outputs=evaluate(PAYLOAD,rules)
    assert variables["alarm_id"]=="a1"
    assert outputs[0]["title"]=="Event CLIENT_CONNECTED"
    assert outputs[0]["message"]=="Site <b>s1</b>"


def test_plain_template_escapes_payload_data():
    assert render("{{ value }}",{"value":"<script>"})=="&lt;script&gt;"


def test_html_template_keeps_static_markup_but_escapes_payload():
    assert render("<b>{{ value }}</b>",{"value":"<script>"},allow_html=True)=="<b>&lt;script&gt;</b>"
