#!/usr/bin/env python3
"""
All-in-one VPS Panel (single-file monolith)
Made by Starvos — Dark-themed admin panel with setup-on-first-run.
Requires: host libvirt/QEMU available at qemu:///system and Docker run with --privileged (or run on host).
"""

import os, sys, time, uuid, subprocess, sqlite3, json
from typing import Optional
from fastapi import FastAPI, Request, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordRequestForm
from jinja2 import Template
from passlib.context import CryptContext
from jose import jwt, JWTError
import libvirt
from urllib.parse import urlencode

# ----------------------------
# Config
# ----------------------------
DB_PATH = os.getenv("STARVOS_DB", "starvos.db")
SECRET_KEY = os.getenv("STARVOS_SECRET", "change_this_secret_now")
JWT_ALGO = "HS256"
DEFAULT_ADMIN = None  # not used, setup required

# ports
WEBSOCKIFY_BASE_PORT = 7000  # websockify will map to 7000,7001,... per console mapping

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI(title="Starvos All-in-One VPS Panel")

# ----------------------------
# Simple embedded templates (dark theme)
# ----------------------------
BASE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{title}}</title>
<style>
/* Minimal dark theme */
:root{
  --bg:#0b0f13; --panel:#0f1720; --muted:#94a3b8; --accent:#7c3aed; --card:#0b1220; --glass: rgba(255,255,255,0.03);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}
html,body{height:100%;margin:0;background:linear-gradient(180deg,#03040b 0%, #071025 100%);color:#e6eef8}
.container{max-width:1100px;margin:32px auto;padding:24px}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:12px}
.logo{width:44px;height:44px;border-radius:8px;background:linear-gradient(135deg,var(--accent),#4c1d95);display:flex;align-items:center;justify-content:center;font-weight:800;color:white}
.title{font-size:20px;font-weight:700}
.panel{background:var(--panel);border-radius:12px;padding:18px;box-shadow: 0 6px 18px rgba(2,6,23,0.6)}
.row{display:flex;gap:12px;flex-wrap:wrap}
.col{flex:1 1 240px}
.btn{background:var(--accent);color:white;padding:8px 12px;border-radius:8px;border:none;cursor:pointer}
.btn-ghost{background:transparent;border:1px solid rgba(255,255,255,0.04);color:var(--muted)}
.form-field{display:flex;flex-direction:column;margin-bottom:10px}
.input{background:var(--card);border:1px solid rgba(255,255,255,0.03);padding:10px;border-radius:8px;color:#e6eef8}
.small{font-size:13px;color:var(--muted)}
.table{width:100%;border-collapse:collapse;margin-top:12px}
.table th, .table td{padding:10px;text-align:left;border-bottom:1px solid rgba(255,255,255,0.03)}
.footer{margin-top:18px;color:var(--muted);font-size:13px;display:flex;justify-content:space-between;align-items:center}
.badge{background:var(--glass);padding:6px 10px;border-radius:999px;font-size:13px}
.notice{background:linear-gradient(90deg, rgba(124,58,237,0.08), rgba(28,27,31,0.06));padding:12px;border-radius:8px;color:var(--muted)}
.link{color:var(--accent);text-decoration:none}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="brand">
      <div class="logo">S</div>
      <div>
        <div class="title">Starvos VPS Panel</div>
        <div class="small">All-in-one • KVM / libvirt panel</div>
      </div>
    </div>
    <div style="text-align:right">
      <div class="badge">Made by Starvos</div>
    </div>
  </div>
  <div class="panel">
    {{content}}
  </div>
  <div class="footer">
    <div class="small">© Starvos • Built with ❤️</div>
    <div class="small">dark theme • convey-style</div>
  </div>
</div>
</body>
</html>"""

SETUP_HTML = """
<h2>Initial Setup</h2>
<p class="small">Welcome! This is the first-time setup. Provide the admin credentials and your panel FQDN. These settings are stored in local database.</p>
<form method="post" action="/setup">
  <div class="form-field"><label class="small">Admin email</label><input class="input" name="email" required /></div>
  <div class="form-field"><label class="small">Admin password</label><input class="input" name="password" type="password" required /></div>
  <div class="form-field"><label class="small">Panel FQDN (example: panel.example.com)</label><input class="input" name="fqdn" required /></div>
  <div style="margin-top:10px"><button class="btn" type="submit">Save & Continue</button></div>
</form>
"""

LOGIN_HTML = """
<h2>Admin Login</h2>
<form method="post" action="/login">
  <div class="form-field"><label class="small">Email</label><input class="input" name="username" required /></div>
  <div class="form-field"><label class="small">Password</label><input class="input" name="password" type="password" required /></div>
  <div style="display:flex;gap:12px;align-items:center">
    <button class="btn" type="submit">Sign in</button>
  </div>
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
    <a class="btn-ghost link" href="/logout">Logout</a>
  </div>
</div>

<div style="margin-top:12px" class="notice">Use the form below to create a VM from an existing qcow2 image path (on the host's /images or container mounted path). Images must exist on the hypervisor.</div>

<form method="post" action="/create-vm" style="margin-top:12px">
  <div class="row">
    <div class="col">
      <div class="form-field"><label class="small">VM Name</label><input class="input" name="name" required /></div>
      <div class="form-field"><label class="small">CPU cores</label><input class="input" name="cpu" type="number" value="1" required /></div>
    </div>
    <div class="col">
      <div class="form-field"><label class="small">Memory (MiB)</label><input class="input" name="memory" type="number" value="1024" required /></div>
      <div class="form-field"><label class="small">Disk image path (qcow2)</label><input class="input" name="image_path" placeholder="/images/ubuntu.qcow2" required /></div>
    </div>
  </div>
  <div style="margin-top:10px"><button class="btn" type="submit">Create VM</button></div>
</form>

<h3 style="margin-top:18px">Running VMs</h3>
<table class="table">
  <thead><tr><th>Name</th><th>UUID</th><th>State</th><th>VNC</th><th>Actions</th></tr></thead>
  <tbody>
    {% for vm in vms %}
    <tr>
      <td>{{vm.name}}</td>
      <td>{{vm.uuid}}</td>
      <td>{{vm.state}}</td>
      <td>{{vm.vnc}}</td>
      <td>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/action">
          <input type="hidden" name="action" value="start" />
          <button class="btn-ghost" type="submit">Start</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/action">
          <input type="hidden" name="action" value="shutdown" />
          <button class="btn-ghost" type="submit">Shutdown</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/action">
          <input type="hidden" name="action" value="reboot" />
          <button class="btn-ghost" type="submit">Reboot</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/console">
          <button class="btn" type="submit">Open Console</button>
        </form>
        <form style="display:inline" method="post" action="/vm/{{vm.uuid}}/delete" onsubmit="return confirm('Delete VM?')">
          <button class="btn-ghost" type="submit">Delete</button>
        </form>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
"""

CONSOLE_HTML = """
<h2>VNC Console for {{name}}</h2>
<p class="small">If a noVNC client appears blank, ensure the VM has a VNC graphics device and that libvirt has assigned a VNC port. Also ensure the container was started --privileged and can access libvirt.</p>
<div style="margin-top:12px">
  <iframe src="{{novnc_url}}" style="width:100%;height:600px;border-radius:8px;border:1px solid rgba(255,255,255,0.03)"></iframe>
</div>
"""

# ----------------------------
# Database helpers (SQLite)
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
    con.commit()
    return con

db = init_db()

def has_admin():
    cur = db.cursor()
    cur.execute("SELECT COUNT(1) as c FROM users WHERE is_admin=1")
    r = cur.fetchone()
    return r["c"] > 0

def create_admin(email, password):
    uid = str(uuid.uuid4())
    h = pwd_ctx.hash(password)
    cur = db.cursor()
    cur.execute("INSERT INTO users(id,email,password_hash,is_admin) VALUES (?,?,?,1)", (uid,email,h))
    db.commit()
    return uid

def verify_user(email, password):
    cur = db.cursor()
    cur.execute("SELECT * FROM users WHERE email=?", (email,))
    r = cur.fetchone()
    if not r: return False
    return pwd_ctx.verify(password, r["password_hash"])

def get_admin_email():
    cur = db.cursor()
    cur.execute("SELECT email FROM users WHERE is_admin=1 LIMIT 1")
    r = cur.fetchone()
    return r["email"] if r else None

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

# ----------------------------
# Libvirt helpers
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
    """Return VNC port if domain has a vnc graphics device, else None"""
    try:
        xml = dom.XMLDesc()
        # simple parse for port='NNNN'
        import re
        m = re.search(r"<graphics[^>]*type='vnc'[^>]*port='(-?\\d+)'[^>]*>", xml)
        if not m: 
            # maybe vnc with a port attribute without quotes or double quotes
            m2 = re.search(r"<graphics[^>]*type=\"vnc\"[^>]*port=\"(-?\\d+)\"[^>]*>", xml)
            if not m2: return None
            else: return int(m2.group(1))
        p = int(m.group(1))
        if p == -1:
            # autoport -> need to query domain for actual port via QEMU monitor? libvirt keeps it in domain.XMLDesc with actual port when running.
            # try look for '<graphics ... port='590x''
            m3 = re.search(r"<graphics[^>]*type='vnc'[^>]*port='(\\d+)'", xml)
            if m3: return int(m3.group(1))
            return None
        return p
    except Exception as e:
        print("vnc parse error", e)
        return None

# small helper to start websockify proxy for a given target host:port -> return local web URL
_WEBSOCKIFY_PROCS = {}  # key -> subprocess
def start_websockify_for(target_host, target_port):
    """
    Launch websockify binding to dynamic port and proxy to target_host:target_port.
    Returns the local http noVNC URL (embedded novnc client) that will connect through websockify.
    """
    # find free proxy port
    base = WEBSOCKIFY_BASE_PORT
    for p in range(base, base+5000):
        if p not in _WEBSOCKIFY_PROCS:
            # spawn websockify on p which proxies to target_host:target_port
            # serve bundled noVNC (system /usr/share/novnc or fallback)
            web_dir = "/usr/share/novnc"
            if not os.path.exists(web_dir):
                # try typical path
                web_dir = "/usr/share/novnc"  # hope exists
            args = ["websockify", "--web", web_dir, f"0.0.0.0:{p}", f"{target_host}:{target_port}"]
            try:
                proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                _WEBSOCKIFY_PROCS[p] = proc
                # return a novnc client URL
                return f"http://{get_setting('fqdn','localhost')}:{p}/vnc.html?host={get_setting('fqdn','localhost')}&port={p}"
            except Exception as e:
                print("Failed to start websockify:", e)
                continue
    raise RuntimeError("No websockify port available")

# ----------------------------
# Pages / Endpoints
# ----------------------------

def render(template_html, **ctx):
    html = Template(BASE_HTML).render(title="Starvos Panel", content=Template(template_html).render(**ctx))
    return HTMLResponse(html)

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    # if no admin yet -> show setup page
    if not has_admin():
        return render(SETUP_HTML)
    # if not logged in -> show login form
    token = request.cookies.get("starvos_token")
    user = decode_jwt(token) if token else None
    if not user:
        return render(LOGIN_HTML)
    # logged in -> show dashboard
    admin = get_admin_email()
    fqdn = get_setting("fqdn", "localhost")
    # fetch vms
    c = libvirt_conn()
    vms = []
    if c:
        # running domains
        try:
            for did in c.listDomainsID():  # returns numeric IDs
                d = c.lookupByID(did)
                vms.append({"name": d.name(), "uuid": d.UUIDString(), "state": domain_state_text(d), "vnc": domain_vnc_port(d)})
            # defined but inactive domains
            for name in c.listDefinedDomains():
                d = c.lookupByName(name)
                vms.append({"name": d.name(), "uuid": d.UUIDString(), "state": domain_state_text(d), "vnc": domain_vnc_port(d)})
        except Exception as e:
            print("libvirt listing err", e)
    return render(DASH_HTML, vms=vms, admin_email=admin, fqdn=fqdn)

@app.post("/setup")
def do_setup(email: str = Form(...), password: str = Form(...), fqdn: str = Form(...)):
    if has_admin():
        return RedirectResponse("/", status_code=303)
    create_admin(email, password)
    set_setting("fqdn", fqdn)
    # create a token cookie
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

@app.post("/create-vm")
def create_vm(request: Request, name: str = Form(...), cpu: int = Form(1), memory: int = Form(1024), image_path: str = Form(...)):
    # require auth
    try:
        user = require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    # create a thin clone using qcow backing file or use image directly (for demo)
    c = libvirt_conn()
    if not c:
        return HTMLResponse("<div style='padding:20px'>libvirt not available. Ensure container has access to libvirt and is privileged.</div>")
    # prepare domain XML with given image_path (user must place images under /images or mount host path)
    vm_uuid = str(uuid.uuid4())
    # Note: Using image directly; production should clone per-instance qcow2 copy
    domain_xml = f"""
    <domain type='kvm'>
      <name>{name}</name>
      <uuid>{vm_uuid}</uuid>
      <memory unit='MiB'>{memory}</memory>
      <vcpu>{cpu}</vcpu>
      <os><type arch='x86_64'>hvm</type></os>
      <devices>
        <disk type='file' device='disk'>
          <driver name='qemu' type='qcow2'/>
          <source file='{image_path}'/>
          <target dev='vda' bus='virtio'/>
        </disk>
        <interface type='network'>
          <source network='default'/>
        </interface>
        <graphics type='vnc' port='-1' autoport='yes'/>
      </devices>
    </domain>
    """
    try:
        dom = c.defineXML(domain_xml)
        if dom is None:
            return HTMLResponse("<div style='padding:20px'>Failed to define VM XML. Check logs.</div>")
        dom.create()
    except Exception as e:
        return HTMLResponse(f"<div style='padding:20px'>Error creating VM: {e}</div>")
    return RedirectResponse("/", status_code=303)

@app.post("/vm/{vm_uuid}/action")
def vm_action(request: Request, vm_uuid: str, action: str = Form(...)):
    try:
        user = require_auth(request)
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
        user = require_auth(request)
    except HTTPException:
        return RedirectResponse("/", status_code=303)
    c = libvirt_conn()
    if not c:
        return HTMLResponse("<div style='padding:20px'>libvirt not available.</div>")
    try:
        dom = c.lookupByUUIDString(vm_uuid)
        # destroy if running
        try:
            if dom.isActive():
                dom.destroy()
        except:
            pass
        dom.undefine()
    except Exception as e:
        return HTMLResponse(f"<div style='padding:20px'>Delete failed: {e}</div>")
    return RedirectResponse("/", status_code=303)

@app.post("/vm/{vm_uuid}/console")
def vm_console(request: Request, vm_uuid: str):
    try:
        user = require_auth(request)
    except HTTPException:
        if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, log_level="info")
