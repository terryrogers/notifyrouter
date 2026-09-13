from notifyrouter.app import create_app


def test_health_and_unconfigured_webhook(tmp_path, monkeypatch):
    monkeypatch.setenv("NOTIFYROUTER_WEBHOOK_TOKEN","test-token")
    app=create_app({"TESTING":True,"DATABASE":str(tmp_path/"test.sqlite3"),"SESSION_COOKIE_SECURE":False})
    client=app.test_client()
    assert client.get("/health").json["status"]=="ok"
    assert client.post("/webhook",json={"test":True}).status_code==401
    response=client.post("/webhook?token=test-token",json={"test":True})
    assert response.status_code==202
    assert response.json["status"]=="no_match"
