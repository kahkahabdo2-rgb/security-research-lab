#!/usr/bin/env python3
"""Owned two-account Mattermost 12.0.2 Synced Drafts native HTTP+WebSocket E2E.
Only short-lived canary content on disposable CI containers. No real credentials.
"""
import json, os, secrets, sys, time
import urllib.request, urllib.error
import websocket

BASE="http://127.0.0.1:8065/api/v4"
results=[]
def probe(name, observed, expected, passed, note=""):
    item={"test":name,"observed":observed,"expected":expected,"pass":bool(passed),"note":note}
    results.append(item)
    print("CHECK "+json.dumps(item,sort_keys=True,ensure_ascii=True),flush=True)

def call(method, path, body=None, token=None):
    headers={"Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    data=json.dumps(body).encode("utf-8") if body is not None else None
    req=urllib.request.Request(BASE+path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req,timeout=25) as response:
            code=response.status; raw=response.read(); hdr=response.headers
    except urllib.error.HTTPError as e:
        code=e.code; raw=e.read(); hdr=e.headers
    try: obj=json.loads(raw.decode()) if raw else None
    except Exception: obj=None
    return code,obj,hdr

def need(code,expected,what):
    if code!=expected: raise RuntimeError(what+" expected "+str(expected)+" got "+str(code))

def login(username,password):
    code,_,headers=call("POST","/users/login",{"login_id":username,"password":password})
    need(code,200,"login "+username)
    token=headers.get("Token")
    if not token: raise RuntimeError("login missing token")
    return token

def has_message(token,team,message):
    code,body,_=call("GET",f"/users/me/teams/{team}/drafts",token=token)
    if code != 200 or not isinstance(body,list):
        raise RuntimeError("GET own drafts failed "+str(code))
    return any(x.get("message")==message for x in body), body

def ws_auth(token):
    ws=websocket.create_connection("ws://127.0.0.1:8065/api/v4/websocket",
        timeout=6,suppress_origin=True)
    ws.send(json.dumps({"seq":1,"action":"authentication_challenge","data":{"token":token}}))
    deadline=time.monotonic()+10
    while time.monotonic()<deadline:
        try: msg=json.loads(ws.recv())
        except websocket.WebSocketTimeoutException: continue
        if msg.get("seq_reply")==1:
            if msg.get("status")!="OK": raise RuntimeError("WS auth not OK")
            ws.settimeout(.20); return ws
    raise RuntimeError("WS auth timeout")

def hit_count(ws,canary,seconds=3):
    hits=0; end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            frame=ws.recv()
            if canary in frame: hits+=1
        except websocket.WebSocketTimeoutException: continue
    return hits

def main():
    ping,_,_=call("GET","/system/ping")
    need(ping,200,"ping")
    suffix=secrets.token_hex(4)
    password="Aa9!"+secrets.token_urlsafe(21)
    ua="dsi_a_"+suffix; ub="dsi_b_"+suffix
    created=[]
    for user in (ua,ub):
        code,body,_=call("POST","/users",
             {"email":user+"@example.invalid","username":user,"password":password})
        need(code,201,"create own test user")
        created.append(body["id"])
    aid,bid=created
    at=login(ua,password); bt=login(ub,password)
    code,team,_=call("POST","/teams",{"name":"dsi"+suffix,"display_name":"DSI owned sandbox","type":"O"},at)
    need(code,201,"create team")
    tid=team["id"]
    code,_,_=call("POST",f"/teams/{tid}/members",{"team_id":tid,"user_id":bid},at)
    need(code,201,"add B to test team")
    def new_channel(name,typ):
        code,body,_=call("POST","/channels",
              {"team_id":tid,"name":name,"display_name":name,"type":typ},at)
        need(code,201,"create test channel")
        return body["id"]
    private=new_channel("p"+suffix,"P")
    shared=new_channel("s"+suffix,"O")
    code,_,_=call("POST",f"/channels/{shared}/members",{"user_id":bid},at)
    need(code,201,"add B to shared channel")
    own_private="DSI_PRIVATE_"+suffix
    code,body,_=call("POST","/drafts",{"channel_id":private,"message":own_private},at)
    need(code,201,"A private draft")
    probe("T01_A_own_private_draft",body.get("user_id"),aid,body.get("user_id")==aid)
    code,_,_=call("POST","/drafts",{"channel_id":private,"message":"FORBIDDEN_"+suffix},bt)
    probe("T02_B_write_A_private_channel",code,"403 or 404",code in (403,404))
    shared_canary="DSI_SHARED_A_"+suffix
    code,body,_=call("POST","/drafts",{"channel_id":shared,"message":shared_canary},at)
    need(code,201,"A own shared draft")
    probe("T03_A_owner_control",body.get("user_id"),aid,body.get("user_id")==aid)
    code,body,_=call("GET",f"/users/{aid}/teams/{tid}/drafts",token=bt)
    leak=code==200 and isinstance(body,list) and any(x.get("message")==shared_canary for x in body)
    probe("T04_B_attempt_A_draft_GET",{"http":code,"canary_visible":leak}, "no canary",not leak)
    code,_,_=call("DELETE",f"/users/{aid}/channels/{shared}/drafts",token=bt)
    visible,_=has_message(at,tid,shared_canary)
    probe("T05_B_attempt_A_draft_DELETE",{"http":code,"A_draft_survived":visible},
          "A draft preserved",visible)
    forged="DSI_FORGED_OWNER_"+suffix
    code,body,_=call("POST","/drafts",{"channel_id":shared,"message":forged,"user_id":aid},bt)
    mine=(code==201 and isinstance(body,dict) and body.get("user_id")==bid)
    a_forged,_=has_message(at,tid,forged)
    probe("T06_B_forge_A_as_owner",{"http":code,"stored_as_B":mine,"in_A_list":a_forged},
          "stored as B only",mine and not a_forged)
    # Prove WS positive and negative controls on both OWNED users.
    ws_a=ws_b=None
    try:
        ws_a=ws_auth(at);ws_b=ws_auth(bt)
        ws_canary="DSI_WS_PRIVATE_"+suffix
        code,_,_=call("POST","/drafts",{"channel_id":shared,"message":ws_canary},at)
        need(code,201,"A WS test draft")
        a_hits=hit_count(ws_a,ws_canary,3)
        b_hits=hit_count(ws_b,ws_canary,3)
        probe("T07_A_receives_own_draft_WS",a_hits,">=1",a_hits>=1)
        probe("T08_B_does_not_receive_A_draft_WS",b_hits,0,b_hits==0 and a_hits>=1,
              "A positive control required")
    finally:
        if ws_a: ws_a.close()
        if ws_b: ws_b.close()
    # A distinct state boundary: post author's delete invalidates all thread reply drafts.
    code,root,_=call("POST","/posts",{"channel_id":shared,"message":"DSI_ROOT_"+suffix},bt)
    need(code,201,"B create own root post")
    rootid=root["id"]
    reply_canary="DSI_A_UNSENT_REPLY_"+suffix
    code,_,_=call("POST","/drafts",
       {"channel_id":shared,"root_id":rootid,"message":reply_canary},at)
    need(code,201,"A create reply draft to B post")
    pre,_=has_message(at,tid,reply_canary)
    code,_,_=call("DELETE",f"/posts/{rootid}",token=bt)
    need(code,200,"B deletes B's own root post")
    absent=False
    for i in range(20):
        still,_=has_message(at,tid,reply_canary)
        if not still: absent=True;break
        time.sleep(.3)
    control,_=has_message(at,tid,shared_canary)
    probe("T09_author_deletes_own_root_affects_other_draft",
      {"A_reply_preexisting":pre,"A_reply_removed":absent,"unrelated_A_draft_preserved":control},
      "record behavior, not automatically a vulnerability",pre and control,
      "Cleanup code intentionally deletes drafts for a removed root post")
    print("RESULTS "+json.dumps({"version_target":"mattermost-team-edition:12.0.2",
       "tests":results,"failed_checks":[t["test"] for t in results if not t["pass"]]},
       sort_keys=True),flush=True)

if __name__=="__main__":
    try: main()
    except Exception as e:
        print("E2E_ERROR "+type(e).__name__+": "+str(e),flush=True);sys.exit(1)
    if any(not r["pass"] for r in results):sys.exit(2)
