import json
import os
import secrets
from functools import wraps

import requests
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from .engine import evaluate, flatten
from .store import Store


def create_app(config=None):
    app=Flask(__name__); app.config.update(SECRET_KEY=os.getenv("CSG_SECRET_KEY") or secrets.token_hex(32),MAX_CONTENT_LENGTH=1024*1024,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE="Strict",SESSION_COOKIE_SECURE=os.getenv("CSG_COOKIE_SECURE","1")=="1")
    if config: app.config.update(config)
    store=Store(app.config.get("DATABASE") or os.getenv("CSG_DATABASE","instance/signal-gateway.sqlite3")); store.init(); app.extensions["store"]=store

    def cipher():
        key=os.getenv("CSG_MASTER_KEY"); return Fernet(key.encode()) if key else None
    def encrypt(value):
        box=cipher(); return box.encrypt(value.encode()).decode() if box and value else ""
    def decrypt(value):
        try:
            box=cipher(); return box.decrypt(value.encode()).decode() if box and value else ""
        except InvalidToken: return ""
    def csrf_ok(): return secrets.compare_digest(session.get("csrf",""),request.form.get("csrf",""))
    def admin_required(fn):
        @wraps(fn)
        def inner(*a,**kw): return fn(*a,**kw) if session.get("admin") else redirect(url_for("login"))
        return inner

    @app.get("/health")
    def health(): return {"status":"ok","product":"CloudHub Signal Gateway"}

    @app.route("/admin/login",methods=["GET","POST"])
    def login():
        if request.method=="POST":
            expected=os.getenv("CSG_ADMIN_PASSWORD_HASH","")
            if expected and check_password_hash(expected,request.form.get("password","")):
                session.clear(); session["admin"]=True; session["csrf"]=secrets.token_urlsafe(24); return redirect(url_for("admin"))
        return render_template("login.html")

    @app.post("/admin/logout")
    @admin_required
    def logout():
        if not csrf_ok(): abort(403)
        session.clear(); return redirect(url_for("login"))

    @app.get("/admin")
    @admin_required
    def admin():
        settings=store.settings(); settings["pushover_configured"]=bool(settings.get("pushover_token") and settings.get("pushover_user")); settings.pop("pushover_token",None); settings.pop("pushover_user",None)
        return render_template("admin.html",rules=store.rules(),settings=settings,events=store.recent(),csrf=session["csrf"])

    @app.post("/admin/settings")
    @admin_required
    def save_settings():
        if not csrf_ok(): abort(403)
        current=store.settings(); values={"app_name":request.form.get("app_name","CloudHub Signal Gateway")}
        for field in ("pushover_token","pushover_user"):
            if request.form.get(field): values[field]=encrypt(request.form[field])
            elif field in current: values[field]=current[field]
        store.set_settings(values); return redirect(url_for("admin"))

    @app.post("/admin/rules")
    @admin_required
    def save_rule():
        if not csrf_ok(): abort(403)
        try: conditions=json.loads(request.form.get("conditions","[]"))
        except json.JSONDecodeError: abort(400,"Conditions must be valid JSON")
        store.save_rule({"id":request.form.get("id") or None,"name":request.form.get("name","Unnamed Rule"),"enabled":"enabled" in request.form,"priority":request.form.get("priority",100),"match_mode":request.form.get("match_mode","all"),"conditions":conditions,"title_template":request.form.get("title_template",""),"message_template":request.form.get("message_template",""),"html":"html" in request.form,"pushover_priority":request.form.get("pushover_priority",0),"sound":request.form.get("sound","pushover"),"stop_processing":"stop_processing" in request.form}); return redirect(url_for("admin"))

    @app.post("/admin/rules/<int:rule_id>/delete")
    @admin_required
    def delete_rule(rule_id):
        if not csrf_ok(): abort(403)
        store.delete_rule(rule_id); return redirect(url_for("admin"))

    @app.post("/admin/inspect")
    @admin_required
    def inspect_payload():
        if not csrf_ok(): abort(403)
        try: payload=json.loads(request.form.get("payload","{}"))
        except json.JSONDecodeError: abort(400,"Payload must be valid JSON")
        variables,outputs=evaluate(payload,store.rules()); return jsonify({"variables":variables,"outputs":outputs})

    def accept_webhook():
        token=os.getenv("CSG_WEBHOOK_TOKEN","")
        supplied=request.headers.get("X-Signal-Gateway-Token") or request.args.get("token","")
        if token and not secrets.compare_digest(token,supplied): abort(401)
        payload=request.get_json(silent=False); variables,outputs=evaluate(payload,store.rules()); settings=store.settings(); statuses=[]
        for output in outputs:
            data={"token":decrypt(settings.get("pushover_token","")),"user":decrypt(settings.get("pushover_user","")),"title":output["title"][:250],"message":output["message"][:1024],"html":int(output["html"]),"priority":output["priority"],"sound":output["sound"]}
            if not data["token"] or not data["user"]: statuses.append("not_configured"); continue
            response=requests.post("https://api.pushover.net/1/messages.json",data=data,timeout=10); statuses.append("sent" if response.ok else f"failed:{response.status_code}")
        status=",".join(statuses) if statuses else "no_match"; store.record(payload,variables,[o["rule"] for o in outputs],status); return jsonify({"accepted":True,"matched_rules":[o["rule"] for o in outputs],"status":status}),202

    app.add_url_rule("/webhook","webhook",accept_webhook,methods=["POST"])
    app.add_url_rule("/alarmid.php","alarmid",accept_webhook,methods=["POST"])
    return app


def main():
    from waitress import serve
    serve(create_app(),host=os.getenv("CSG_HOST","127.0.0.1"),port=int(os.getenv("CSG_PORT","8080")))


if __name__ == "__main__": main()

