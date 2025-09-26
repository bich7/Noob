#!/usr/bin/env python3
"""
made by starvos All-in-one VPS Panel (single-file)
Features:
 - Web UI (dark theme) + REST API
 - Admin setup, login, add users
 - Templates management (register base qcow2 images)
 - Create VMs from templates: CPU, RAM, Disk size, Name
 - VM lifecycle: start/stop/reboot/delete (deletes disk file)
 - Console via websockify + noVNC
 - Uses libvirt (qemu:///system) and qemu-img for disk ops
 - Stores metadata in SQLite
"""
import os
import sys
import uuid
import time
import json
import sqlite3
import subprocess
from typing import Optional, List
from urllib.parse import urlencode

from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from jinja2 import Template
from passlib.context import CryptContext
from jose import jwt, JWTError

import libvirt
import re

# ----------------------------
# Configuration
# ----------------------------
DB_PATH = os.getenv("STARVOS_DB", "starvos.db")
SECRET_KEY = os.getenv("STARVOS_SECRET", "change_this_secret_now")
JWT_ALGO = "HS256"
WEBSOCKIFY_BASE_PORT = int(os.getenv("WEBSOCKIFY_BASE_PORT", "7000"))
IMAGES_DIR = os.getenv("IMAGES_DIR", "/var/lib/libvirt/images")  # fallback to /tmp if not writable

# Ensure images dir exists or fallback
if not os.path.exists(IMAGES_DIR):
    try:
        os.makedirs(IMAGES_DIR, exist_ok=True)
    except Exception:
        IMAGES_DIR = "/tmp"

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="Convey-style VPS Panel")

# ----------------------------
# Templates (dark theme)
# ----------------------------
BASE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title>
<style>
:root{--bg:#0b0f13;--panel:#0f1720;--muted:#94a3b8;--accent:#7c3aed;--card:#0b1220}
html,body{height:100%;margin:0;background:linear-gradient(180deg,#03040b 0%, #071025 100%);color:#e6eef8;font-family:Inter,system-ui,Segoe UI,Roboto,Arial}
.container{max-width:1100px;margin:28px auto;padding:20px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.brand{display:flex;gap:12px;align-items:center}
.logo{width:44px;height:44px;border-radius:10px;background:linear-gradient(135deg,var(--accent),#4c1d95);display:flex;align-items:center;justify-content:center;font-weight:800;color:white}
.title{font-size:20px;font-weight:700}
.panel{background:var(--panel);border-radius:12px;padding:18px;box-shadow:0 6px 18px rgba(2,6,23,0.6)}
.row{display:flex;gap:12px;flex-wrap:wrap}
.col{flex:1 1 240px}
.btn{background:var(--accent);color:white;padding:8px 12px;border-radius:8px;border:none;cursor:pointer}
.btn-ghost{background:transparent;border:1px solid rgba(255,255,255,0.04);color:var(--muted);padding:8px 10px;border-radius:8px}
.form-field{display:flex;flex-direction:column;margin-bottom:10px}
.input{background:var(--card);border:1px solid rgba(255,255,255,0.03);padding:10px;border-radius:8px;color:#e6eef8}
.small{font-size:13px;color:var(--muted)}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th,.table td{padding:10px;text-align:left;border-bottom:1px solid rgba(255,255,255,0.03)}
.footer{margin-top:18px;color:var(--muted);font-size:13px;display:flex;justify-content:space-between;align-items:center}
.badge{background:rgba(255,255,255,0.03);padding:6px 10px;border-radius:999px;font-size:13px}
.notice{background:linear-gradient(90deg, rgba(124,58,237,0.06), rgba(28,27,31,0.04));padding:12px;border-radius:8px;color:var(--muted)}
.select{background:var(--card);border:1px solid rgba(255,255,255,0.03);padding:10px;border-radius:8px;color:#e6eef8}
</style></head><body>
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo">S</div>
      <div>
        <div class="title">Starvos - Convey-style VPS Panel</div>
        <div class="small">KVM / libvirt • single-file panel</div>
      </div>
    </div>
    <div style="text-align:right">
      <div class="badge">Made by Starvos</div>
    </div>
  </div>
  <div class="panel">{{content}}</div>
  <div class="footer">
    <div class="small">© Starvos • Built with ❤️</div>
    <div class="small">Convey-style single-file panel</div>
  </div>
</div></body></html>
"""

SETUP_HTML = """
<h2>Initial Setup</h2>
<p class="small">Create initial admin account and panel FQDN.</p>
<form method="post" action="/setup">
  <div class="form-field"><label class="small">Admin email</label><input class="input" name="email" required></div>
  <div class="form-field"><label class="small">Admin password</label><input class="input" name="password" type="password" required></div>
  <div class="form-field"><label class="small">Panel FQDN (for console links)</label><input class="input" name="fqdn" value="localhost" required></div>
  <div style="margin-top:10px"><button class="btn" type="submit">Create Admin</button></div>
</form>
"""

LOGIN_HTML = """
<h2>Admin Login</h2>
<form method="post" action="/login">
  <div class="form-field"><label class="small">Email</label><input class="input" name="username" required></div>
  <div class="form-field"><label class="small">Password</label><input class="input" name="password" type="password" required></div>
  <div style="display:flex;gap:12px;align-items:center"><button class="btn" type="submit">Sign in</button></div>
</form>
"""

DASH_HTML = """
<h2>Dashboard</h2>
<div style="display:flex;justify-content:space-between;align-items:center">
  <div>
    <div class="small">Panel FQDN: <strong>{{fqdn}}</strong></div>
    <div class="small">Admin: <strong>{{admin_email}}</strong></div>
  </div>
  <div>
    <a class="btn-ghost link" href="/templates">Templates</a>
    <a class="btn-ghost link" href="/users">Users</a>
    <a class="btn-ghost link" href="/logout">Logout</a>
  </div>
</div>

<div style="margin-top:12px" class="notice">Create a new VM from a registered template (or enter a direct base image path).</div>

<form method="post" action="/create-vm" style="margin-top:12px">
  <div class="row">
    <div class="col">
      <div class="form-field"><label class="small">VM Name</label><input class="input" name="name" required></div>
      <div class="form-field"><label class="small">CPU cores</label><input class="input" name="cpu" type="number" value="1" required></div>
      <div class="form-field"><label class="small">Memory (MiB)</label><input class="input" name="memory" type="number" value="1024" required></div>
    </div>
    <div class="col">
      <div class="form-field"><label class="small">Disk size (GiB)</label><input class="input" name="disk_size" type="number" value="20" required></div>
      <div class="form-field"><label class="small">Template</label>
        <select class="select" name="template_id">
          <option value="">-- choose template --</option>
          {% for t in templates %}
            <option value="{{t.id}}">{{t.name}} ({{t.path}})</option>
          {% endfor %}
        </select>
      </div>
      <div class="form-field"><label class="small">Or Base image path (qcow2)</label><input class="input" name="image_path" placeholder="/images/ubuntu.qcow2"></div>
    </div>
  </div>
  <div style="margin-top:10px"><button class="btn" type="submit">Create VM</button></div>
</form>

<h3 style="margin-top:18px">VMs</h3>
<table class="table">
  <thead><tr><th>Name</th><th>UUID</th><th>CPU</th><th>RAM (MiB)</th><th>Disk (GiB)</th><th>State</th><th>VNC</th><th>Actions</th></tr></thead>
  <tbody>
    {% for vm in vms %}
    <tr>
      <td>{{vm.name}}</td>
      <td>{{vm.uuid}}</td>
      <td>{{vm.cpu}}</td>
      <td>{{vm.memory}}</td>
      <td>{{vm.disk_size}}</td>
      <td>{{vm.state}}</td>
      <td>{{vm.vnc}}</td>
      <td>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/action">
          <input type="hidden" name="action" value="start"><button class="btn-ghost" type="submit">Start</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/action">
          <input type="hidden" name="action" value="shutdown"><button class="btn-ghost" type="submit">Shutdown</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/action">
          <input type="hidden" name="action" value="reboot"><button class="btn-ghost" type="submit">Reboot</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/console">
          <button class="btn" type="submit">Console</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/delete" onsubmit="return confirm('Delete VM and disk?')">
          <button class="btn-ghost" type="submit">Delete</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
"""

TEMPLATES_HTML = """
<h2>Templates</h2>
<p class="small">Register base qcow2 images here so they show up in the create VM dropdown.</p>
<form method="post" action="/templates/add">
  <div class="row">
    <div class="col">
      <div class="form-field"><label class="small">Template name</label><input class="input" name="name" required></div>
      <div class="form-field"><label class="small">Image path (qcow2)</label><input class="input" name="path" required></div>
    </div>
  </div>
  <div style="margin-top:10px"><button class="btn" type="submit">Add Template</button> <a class="btn-ghost link" href="/">Back</a></div>
</form>

<h3 style="margin-top:18px">Registered templates</h3>
<table class="table"><thead><tr><th>Name</th><th>Path</th><th>Actions</th></tr></thead><tbody>
{% for t in templates %}
<tr>
  <td>{{t.name}}</td>
  <td>{{t.path}}</td>
  <td>
    <form style="display:inline" method="post" action="/templates/{{t.id}}/delete" onsubmit="return confirm('Delete template?')">
      <button class="btn-ghost" type="submit">Delete</button>
    </form>
  </td>
</tr>
{% endfor %}
</tbody></table>
"""

USERS_HTML = """
<h2>Users</h2>
<p class="small">Create regular users here. Admins can manage templates and VMs.</p>
<form method="post" action="/users/add">
  <div class="row">
    <div class="col">
      <div class="form-field"><label class="small">Email</label><input class="input" name="email" required></div>
      <div class="form-field"><label class="small">Password</label><input class="input" name="password" required></div>
      <div class="form-field"><label class="small">Is admin?</label><select class="select" name="is_admin"><option value="0">No</option><option value="1">Yes</option></select></div>
    </div>
  </div>
  <div style="margin-top:10px"><button class="btn" type="submit">Create User</button> <a class="btn-ghost link" href="/">Back</a></div>
</form>

<h3 style="margin-top:18px">All users</h3>
<table class="table"><thead><tr><th>Email</th><th>Admin</th><th>Actions</th></tr></thead><tbody>
{% for u in users %}
<tr>
  <td>{{u.email}}</td>
  <td>{{'Yes' if u.is_admin else 'No'}}</td>
  <td>
    <form style="display:inline" method="post" action="/users/{{u.id}}/toggle">
      <button class="btn-ghost" type="submit">{{'Demote' if u.is_admin else 'Promote'}}</button>
    </form>
  </td>
</tr>
{% endfor %}
</tbody></table>
"""

CONSOLE_HTML = """
<h2>VNC Console for {{name}}</h2>
<p class="small">If blank, ensure VM has VNC device and libvirt/QEMU is reachable from this host.</p>
<iframe src="{{novnc_url}}" style="width:100%;height:640px;border-radius:8px;border:1px solid rgba(255,255,255,0.03)"></iframe>
"""

# ----------------------------
# Database helpers
# ----------------------------
def get_conn():
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = get_conn()
    cur = con.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, email TEXT UNIQUE, password_hash TEXT, is_admin INTEGER DEFAULT 0
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY, value TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS templates (
        id TEXT PRIMARY KEY, name TEXT, path TEXT
    )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS vms (
        id TEXT PRIMARY KEY, name TEXT, uuid TEXT, cpu INTEGER, memory INTEGER, disk_path TEXT, disk_size INTEGER, template_id TEXT, owner_email TEXT
    )""")
    con.commit()
    return con

db = init_db()

# ----------------------------
# Auth helpers (JWT)
# ----------------------------
def create_jwt(email):
    payload = {"sub": email}
    token = jwt.encode(payload, SECRET_KEY, algorithm=JWT_ALGO)
    return token

def decode_jwt(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGO])
        return payload.get("sub")
    except JWTError:
        return None

def require_auth(request: Request):
    token = request.cookies.get("starvos_token")
    if not token:
        raise HTTPException(status_code=303, detail="Not authenticated")
    user = decode_jwt(token)
    if not user:
        raise HTTPException(status_code=303, detail="Invalid token")
    return user

def require_api_auth(request: Request):
    # API token from Authorization: Bearer <token>
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = auth.split(None, 1)[1]
    user = decode_jwt(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

# ----------------------------
# Utility / libvirt helpers
# ----------------------------
def libvirt_conn(uri="qemu:///system"):
    try:
        c = libvirt.open(uri)
        return c
    except Exception as e:
        print("libvirt connect error:", e)
        return None

def domain_state_text(dom):
    try:
        st = dom.info()[0]
        mapstate = {1:"running", 3:"paused", 5:"shutoff"}
        return mapstate.get(st, str(st))
    except:
        return "unknown"

def domain_vnc_port(dom):
    try:
        xml = dom.XMLDesc()
        m = re.search(r"<graphics[^>]*type=['\"]vnc['\"][^>]*port=['\"]?(-?\d+)['\"]?", xml)
        if not m:
            return None
        p = int(m.group(1))
        if p == -1:
            # sometimes libvirt will show -1; try to find actual
            m2 = re.search(r"<graphics[^>]*type=['\"]vnc['\"][^>]*port=['\"](\d+)['\"]", dom.XMLDesc())
            if m2:
                return int(m2.group(1))
            return None
        return p
    except Exception as e:
        print("vnc parse error", e)
        return None

_WEBSOCKIFY_PROCS = {}
def start_websockify_for(target_host, target_port):
    base = WEBSOCKIFY_BASE_PORT
    for p in range(base, base+5000):
        if p not in _WEBSOCKIFY_PROCS:
            web_dir = "/usr/share/novnc"
            if not os.path.exists(web_dir):
                web_dir = "/usr/share/novnc"  # hope available
            args = ["websockify", "--web", web_dir, f"0.0.0.0:{p}", f"{target_host}:{target_port}"]
            try:
                proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                _WEBSOCKIFY_PROCS[p] = proc
                fqdn = get_setting("fqdn", "localhost")
                return f"http://{fqdn}:{p}/vnc.html?host={fqdn}&port={p}"
            except Exception as e:
                print("Failed to start websockify:", e)
                continue
    raise RuntimeError("No websockify port available")

# ----------------------------
# Settings helpers
# ----------------------------
def set_setting(key, value):
    cur = db.cursor()
    cur.execute("INSERT OR REPLACE INTO settings(key,value) VALUES (?,?)", (key, value))
    db.commit()

def get_setting(key, default=None):
    cur = db.cursor()
    cur.execute("SELECT value FROM settings WHERE key=?", (key,))
    r = cur.fetchone()
    return r["value"] if r else default

# ----------------------------
# Templates DB helpers
# ----------------------------
def add_template(name, path):
    tid = str(uuid.uuid4())
    cur = db.cursor()
    cur.execute("INSERT INTO templates(id,name,path) VALUES (?,?,?)", (tid, name, path))
    db.commit()
    return tid

def list_templates():
    cur = db.cursor()
    cur.execute("SELECT id,name,path FROM templates ORDER BY name")
    return [dict(row) for row in cur.fetchall()]

def get_template(tid):
    cur = db.cursor()
    cur.execute("SELECT id,name,path FROM templates WHERE id=?", (tid,))
    r = cur.fetchone()
    return dict(r) if r else None

def delete_template(tid):
    cur = db.cursor()
    cur.execute("DELETE FROM templates WHERE id=?", (tid,))
    db.commit()

# ----------------------------
# Users DB helpers
# ----------------------------
def create_admin(email, password):
    uid = str(uuid.uuid4())
    h = pwd_ctx.hash(password)
    cur = db.cursor()
    cur.execute("INSERT INTO users(id,email,password_hash,is_admin) VALUES (?,?,?,1)", (uid,email,h))
    db.commit()
    return uid

def create_user(email, password, is_admin=False):
    uid = str(uuid.uuid4())
    h = pwd_ctx.hash(password)
    cur = db.cursor()
    cur.execute("INSERT INTO users(id,email,password_hash,is_admin) VALUES (?,?,?,?)", (uid,email,h,1 if is_admin else 0))
    db.commit()
    return uid

def has_admin():
    cur = db.cursor()
    cur.execute("SELECT COUNT(1) as c FROM users WHERE is_admin=1")
    r = cur.fetchone()
    return r["c"] > 0

def verify_user(email, password):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    r = cur.fetchone()
    if not r: return False
    return pwd_ctx.verify(password, r["password_hash"])

def list_users():
    cur = db.cursor()
    cur.execute("SELECT id,email,is_admin FROM users ORDER BY email")
    return [dict(row) for row in cur.fetchall()]

def toggle_admin(uid):
    cur = db.cursor()
    cur.execute("SELECT is_admin FROM users WHERE id=?", (uid,))
    r = cur.fetchone()
    if not r: return False
    new = 0 if r["is_admin"] else 1
    cur.execute("UPDATE users SET is_admin=? WHERE id=?", (new, uid))
    db.commit()
    return True

def get_user_by_email(email):
    cur = db.cursor()
    cur.execute("SELECT id,email,is_admin FROM users WHERE email=?", (email,))
    r = cur.fetchone()
    return dict(r) if r else None

# ----------------------------
# VM DB helpers
# ----------------------------
def add_vm_record(name, uuidstr, cpu, memory, disk_path, disk_size, template_id=None, owner_email=None):
    vid = str(uuid.uuid4())
    cur = db.cursor()
    cur.execute("INSERT INTO vms(id,name,uuid,cpu,memory,disk_path,disk_size,template_id,owner_email) VALUES (?,?,?,?,?,?,?,?,?)",
                (vid, name, uuidstr, cpu, memory, disk_path, disk_size, template_id, owner_email))
    db.commit()
    return vid

def list_vm_records():
    cur = db.cursor()
    cur.execute("SELECT * FROM vms ORDER BY name")
    return [dict(row) for row in cur.fetchall()]

def get_vm_record_by_uuid(uuidstr):
    cur = db.cursor()
    cur.execute("SELECT * FROM vms WHERE uuid=?", (uuidstr,))
    r = cur.fetchone()
    return dict(r) if r else None

def delete_vm_record(uuidstr):
    cur = db.cursor()
    cur.execute("DELETE FROM vms WHERE uuid=?", (uuidstr,))
    db.commit()

# ----------------------------
# Rendering helper
# ----------------------------
def render(template_html, **ctx):
    html = Template(BASE_HTML).render(title="Starvos Panel", content=Template(template_html).render(**ctx))
    return HTMLResponse(html)

# ----------------------------
# Pages / endpoints
# ----------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # initial setup
    if not has_admin():
        return render(SETUP_HTML)
    token = request.cookies.get("starvos_token")
    user = decode_jwt(token) if token else None
    if not user:
        return render(LOGIN_HTML)
    # logged in -> dashboard
    admin_email = get_setting("admin_email", user)
    fqdn = get_setting("fqdn", "localhost")
    # collect templates
    templates = list_templates()
    # libvirt list
    c = libvirt_conn()
    vms = []
    records = list_vm_records()
    if c:
        try:
            # running domains
            for did in c.listDomainsID():
                d = c.lookupByID(did)
                rec = get_vm_record_by_uuid(d.UUIDString())
                vnc = domain_vnc_port(d)
                vms.append({
                    "name": d.name(),
                    "uuid": d.UUIDString(),
                    "cpu": rec["cpu"] if rec else d.maxVcpus(),
                    "memory": rec["memory"] if rec else (d.info()[1]//1024),
                    "disk_size": rec["disk_size"] if rec else (rec["disk_size"] if rec else ""),
                    "state": domain_state_text(d),
                    "vnc": vnc or ""
                })
            for name in c.listDefinedDomains():
                d = c.lookupByName(name)
                rec = get_vm_record_by_uuid(d.UUIDString())
                vnc = domain_vnc_port(d)
                vms.append({
                    "name": d.name(),
                    "uuid": d.UUIDString(),
                    "cpu": rec["cpu"] if rec else d.maxVcpus(),
                    "memory": rec["memory"] if rec else (d.info()[1]//1024),
                    "disk_size": rec["disk_size"] if rec else "",
                    "state": domain_state_text(d),
                    "vnc": vnc or ""
                })
        except Exception as e:
            print("libvirt listing err", e)
    # include records that might not be defined in libvirt yet
    known_uuids = {v["uuid"] for v in vms}
    for rec in records:
        if rec["uuid"] not in known_uuids:
            vms.append({
                "name": rec["name"],
                "uuid": rec["uuid"],
                "cpu": rec["cpu"],
                "memory": rec["memory"],
                "disk_size": rec["disk_size"],
                "state": "defined",
                "vnc": ""
            })
    return render(DASH_HTML, fqdn=fqdn, admin_email=admin_email, templates=templates, vms=vms)

@app.post("/setup")
def do_setup(email: str = Form(...), password: str = Form(...), fqdn: str = Form(...)):
    if has_admin():
        return RedirectResponse("/", status_code=303)
    create_admin(email, password)
    set_setting("fqdn", fqdn)
    set_setting("admin_email", email)
    token = create_jwt(email)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("starvos_token", token, httponly=True, samesite="lax")
    return response

@app.post("/login")
def do_login(form: OAuth2PasswordRequestForm = Depends()):
    if not verify_user(form.username, form.password):
        return HTMLResponse("<div style='padding:20px'>Invalid credentials. <a href='/'>Back</a></div>", status_code=401)
    token = create_jwt(form.username)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie("starvos_token", token, httponly=True, samesite="lax")
    return response

@app.get("/logout")
def logout():
    r = RedirectResponse("/", status_code=303)
    r.delete_cookie("starvos_token")
    return r

# ----------------------------
# Templates pages & actions
# ----------------------------
@app.get("/templates", response_class=HTMLResponse)
def templates_page(request: Request):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    templates = list_templates()
    return render(TEMPLATES_HTML, templates=templates)

@app.post("/templates/add")
def templates_add(request: Request, name: str = Form(...), path: str = Form(...)):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    # basic check, not enforced — admin should ensure path exists on host
    add_template(name, path)
    return RedirectResponse("/templates", status_code=303)

@app.post("/templates/{tid}/delete")
def templates_delete(request: Request, tid: str):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    delete_template(tid)
    return RedirectResponse("/templates", status_code=303)

# ----------------------------
# Users pages & actions
# ----------------------------
@app.get("/users", response_class=HTMLResponse)
def users_page(request: Request):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    users = list_users()
    return render(USERS_HTML, users=users)

@app.post("/users/add")
def users_add(request: Request, email: str = Form(...), password: str = Form(...), is_admin: int = Form(0)):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    create_user(email, password, is_admin=bool(int(is_admin)))
    return RedirectResponse("/users", status_code=303)

@app.post("/users/{uid}/toggle")
def users_toggle(request: Request, uid: str):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    toggle_admin(uid)
    return RedirectResponse("/users", status_code=303)

# ----------------------------
# VM create / actions / delete / console
# ----------------------------
@app.post("/create-vm")
def create_vm(request: Request,
              name: str = Form(...),
              cpu: int = Form(1),
              memory: int = Form(1024),
              disk_size: int = Form(20),
              template_id: str = Form(""),
              image_path: str = Form("")
             ):
    try:
        user = require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)

    # Decide base image
    base = None
    if template_id:
        t = get_template(template_id)
        if not t:
            return HTMLResponse("<div style='padding:20px'>Template not found</div>")
        base = t["path"]
    elif image_path:
        base = image_path
    else:
        return HTMLResponse("<div style='padding:20px'>No template or image provided.</div>")

    # Ensure base exists on host (we don't copy/upload in panel)
    if not os.path.exists(base):
        return HTMLResponse(f"<div style='padding:20px'>Base image not found on host: {base}</div>")

    c = libvirt_conn()
    if not c:
        return HTMLResponse("<div style='padding:20px'>libvirt not available. Run with access to host libvirt.</div>")

    vm_uuid = str(uuid.uuid4())
    vm_disk = os.path.join(IMAGES_DIR, f"{name}-{vm_uuid}.qcow2")

    # Create qcow2 using backing file for thin-provision, then resize
    try:
        # Thin clone using backing file
        subprocess.run(["qemu-img", "create", "-f", "qcow2", "-b", base, vm_disk], check=True)
        subprocess.run(["qemu-img", "resize", vm_disk, f"{disk_size}G"], check=True)
        # If you prefer a full independent copy (no backing), use:
        # subprocess.run(["qemu-img", "create", "-f", "qcow2", vm_disk, f"{disk_size}G"], check=True)
        # subprocess.run(["qemu-img", "convert", "-O", "qcow2", base, vm_disk], check=True)
    except subprocess.CalledProcessError as e:
        return HTMLResponse(f"<div style='padding:20px'>qemu-img failed: {e}</div>")

    # Build domain xml
    domain_xml = f"""
    <domain type='kvm'>
      <name>{name}</name>
      <uuid>{vm_uuid}</uuid>
      <memory unit='MiB'>{memory}</memory>
      <vcpu placement='static'>{cpu}</vcpu>
      <os>
        <type arch='x86_64' machine='pc'>hvm</type>
      </os>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='{vm_disk}'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <interface type='network'>
          <source network='default'/>
        </interface>
        <graphics type='vnc' port='-1' autoport='yes'/>
        <console type='pty'/>
      </devices>
    </domain>
    """

    try:
        dom = c.defineXML(domain_xml)
        if dom is None:
            return HTMLResponse("<div style='padding:20px'>Failed to define VM XML. Check libvirt logs.</div>")
        dom.create()
    except Exception as e:
        # cleanup disk if defined failed
        try:
            if os.path.exists(vm_disk):
                os.remove(vm_disk)
        except: pass
        return HTMLResponse(f"<div style='padding:20px'>Error creating VM: {e}</div>")

    # Save metadata
    add_vm_record(name, vm_uuid, cpu, memory, vm_disk, disk_size, template_id, owner_email=user)
    return RedirectResponse("/", status_code=303)

@app.post("/vm/{vm_uuid}/action")
def vm_action(request: Request, vm_uuid: str, action: str = Form(...)):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    c = libvirt_conn()
    if not c:
        return HTMLResponse("<div style='padding:20px'>libvirt not available.</div>")
    try:
        dom = c.lookupByUUIDString(vm_uuid)
    except:
        return HTMLResponse("<div style='padding:20px'>VM not found</div>")
    try:
        if action == "start":
            dom.create()
        elif action == "shutdown":
            dom.shutdown()
        elif action == "reboot":
            dom.reboot()
        else:
            return HTMLResponse("<div style='padding:20px'>Unknown action</div>")
    except Exception as e:
        return HTMLResponse(f"<div style='padding:20px'>Action failed: {e}</div>")
    return RedirectResponse("/", status_code=303)

@app.post("/vm/{vm_uuid}/delete")
def vm_delete(request: Request, vm_uuid: str):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    c = libvirt_conn()
    if not c:
        return HTMLResponse("<div style='padding:20px'>libvirt not available.</div>")
    # attempt to find domain and undefine/destroy
    try:
        dom = c.lookupByUUIDString(vm_uuid)
        try:
            if dom.isActive():
                dom.destroy()
        except:
            pass
        # fetch disk from XML
        try:
            xml = dom.XMLDesc()
            m = re.search(r"<source file=['\"]([^'\"]+)['\"]", xml)
            if m:
                disk_path = m.group(1)
            else:
                disk_path = None
        except:
            disk_path = None
        dom.undefine()
    except Exception as e:
        disk_path = None
        # maybe domain not defined; we still try to remove metadata
    # Remove disk file recorded in DB
    rec = get_vm_record_by_uuid(vm_uuid)
    if rec:
        dp = rec.get("disk_path")
        try:
            if dp and os.path.exists(dp):
                os.remove(dp)
        except Exception:
            pass
        delete_vm_record(vm_uuid)
    # Also if we discovered disk_path earlier, remove
    try:
        if disk_path and os.path.exists(disk_path):
            os.remove(disk_path)
    except:
        pass
    return RedirectResponse("/", status_code=303)

@app.post("/vm/{vm_uuid}/console")
def vm_console(request: Request, vm_uuid: str):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    c = libvirt_conn()
    if not c:
        return HTMLResponse("<div style='padding:20px'>libvirt not available.</div>")
    try:
        dom = c.lookupByUUIDString(vm_uuid)
    except Exception as e:
        return HTMLResponse("<div style='padding:20px'>VM not found</div>")
    vncport = domain_vnc_port(dom)
    if vncport is None:
        return HTMLResponse("<div style='padding:20px'>No VNC graphics detected for this VM.</div>")
    try:
        probe_host = "127.0.0.1"
        novnc_url = start_websockify_for(probe_host, vncport)
    except Exception as e:
        return HTMLResponse(f"<div style='padding:20px'>Failed to start console proxy: {e}</div>")
    return render(CONSOLE_HTML, name=dom.name(), novnc_url=novnc_url)

# ----------------------------
# REST API (basic)
# ----------------------------
@app.post("/api/login")
def api_login(form: OAuth2PasswordRequestForm = Depends()):
    if not verify_user(form.username, form.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_jwt(form.username)
    return {"token": token}

@app.get("/api/templates")
def api_templates(user=Depends(require_api_auth)):
    return {"templates": list_templates()}

@app.post("/api/templates/add")
def api_templates_add(name: str = Form(...), path: str = Form(...), user=Depends(require_api_auth)):
    add_template(name, path)
    return {"ok": True}

@app.get("/api/vms")
def api_vms(user=Depends(require_api_auth)):
    # return DB records and libvirt state
    c = libvirt_conn()
    vms = []
    for rec in list_vm_records():
        state = "unknown"
        vnc = None
        try:
            if c:
                dom = c.lookupByUUIDString(rec["uuid"])
                state = domain_state_text(dom)
                vnc = domain_vnc_port(dom)
        except:
            state = "defined"
        rec2 = dict(rec)
        rec2["state"] = state
        rec2["vnc"] = vnc
        vms.append(rec2)
    return {"vms": vms}

@app.post("/api/vm/create")
def api_vm_create(name: str = Form(...), cpu: int = Form(1), memory: int = Form(1024), disk_size: int = Form(20),
                  template_id: str = Form(""), image_path: str = Form(""), user=Depends(require_api_auth)):
    # reuse create_vm internals (simple duplicate)
    # choose base
    base = None
    if template_id:
        t = get_template(template_id)
        if not t:
            raise HTTPException(status_code=400, detail="Template not found")
        base = t["path"]
    elif image_path:
        base = image_path
    else:
        raise HTTPException(status_code=400, detail="No base provided")
    if not os.path.exists(base):
        raise HTTPException(status_code=400, detail="Base image not found on host")
    c = libvirt_conn()
    if not c:
        raise HTTPException(status_code=500, detail="libvirt not available")
    vm_uuid = str(uuid.uuid4())
    vm_disk = os.path.join(IMAGES_DIR, f"{name}-{vm_uuid}.qcow2")
    try:
        subprocess.run(["qemu-img", "create", "-f", "qcow2", "-b", base, vm_disk], check=True)
        subprocess.run(["qemu-img", "resize", vm_disk, f"{disk_size}G"], check=True)
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"qemu-img failed: {e}")
    domain_xml = f"""
    <domain type='kvm'>
      <name>{name}</name>
      <uuid>{vm_uuid}</uuid>
      <memory unit='MiB'>{memory}</memory>
      <vcpu placement='static'>{cpu}</vcpu>
      <os><type arch='x86_64'>hvm</type></os>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='{vm_disk}'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <interface type='network'><source network='default'/></interface>
        <graphics type='vnc' port='-1' autoport='yes'/>
      </devices>
    </domain>
    """
    try:
        dom = c.defineXML(domain_xml)
        if dom is None:
            raise HTTPException(status_code=500, detail="Failed to define domain")
        dom.create()
    except Exception as e:
        try:
            if os.path.exists(vm_disk):
                os.remove(vm_disk)
        except: pass
        raise HTTPException(status_code=500, detail=f"Failed to create VM: {e}")
    add_vm_record(name, vm_uuid, cpu, memory, vm_disk, disk_size, template_id, owner_email=user)
    return {"ok": True, "uuid": vm_uuid}

# ----------------------------
# CLI runner
# ----------------------------
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()
    init_db()
    import uvicorn
    uvicorn.run("main:app", host=args.host, port=args.port, log_level="info")
