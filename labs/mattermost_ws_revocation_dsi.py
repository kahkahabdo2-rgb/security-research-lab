#!/usr/bin/env python3
"""E2E on unmodified Mattermost 12.0.2.
Two owned users; warm WS membership then revoke B before publishing distinct private canaries.
No repeated requests/fuzzing/DoS; three posts only.
"""
import json,os,secrets,time,sys,urllib.request,urllib.error
import websocket
BASE="http://127.0.0.1:8065/api/v4"
OUT=[]
def call(m,path,obj=None,token=None):
    headers={"Content-Type":"application/json"}
    if token:headers["Authorization"]="Bearer "+token
    dat=json.dumps(obj).encode() if obj is not None else None
    req=urllib.request.Request(BASE+path,data=dat,headers=headers,method=m)
    try:
        with urllib.request.urlopen(req,timeout=18) as r:status=r.status;raw=r.read();hdr=r.headers
    except urllib.error.HTTPError as e:status=e.code;raw=e.read();hdr=e.headers
    try:reply=json.loads(raw.decode()) if raw else None
    except Exception:reply=None
    return status,reply,hdr
def chk(name,passed,value,expect):
    d={"test":name,"pass":bool(passed),"observed":value,"expected":expect}
    OUT.append(d);print("CHECK "+json.dumps(d,sort_keys=True),flush=True)
def need(status,expected,what):
    if status!=expected:raise RuntimeError(what+" expected "+str(expected)+" observed "+str(status))
def login(name,pw):
    st,_,hd=call("POST","/users/login",{"login_id":name,"password":pw})
    need(st,200,"login")
    return hd["Token"]
def connect(tok):
    w=websocket.create_connection("ws://127.0.0.1:8065/api/v4/websocket",timeout=7)
    w.send(json.dumps({"seq":1,"action":"authentication_challenge","data":{"token":tok}}))
    end=time.monotonic()+8
    while time.monotonic()<end:
        try:obj=json.loads(w.recv())
        except websocket.WebSocketTimeoutException:continue
        if obj.get("seq_reply")==1:
            if obj.get("status")!="OK":raise RuntimeError("ws authentication failed")
            w.settimeout(.25);return w
    raise RuntimeError("ws authentication timeout")
def events(w,seconds):
    res=[];end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:res.append(json.loads(w.recv()))
        except websocket.WebSocketTimeoutException:continue
        except Exception as e:raise RuntimeError("ws read "+type(e).__name__)
    return res
def sent_post(frames,canary):
    return sum(1 for f in frames if f.get("event")=="posted" and canary in json.dumps(f))
def send(tok,channel,body):
    st,obj,_=call("POST","/posts",{"channel_id":channel,"message":body},tok)
    need(st,201,"post");return obj["id"]
def main():
    sf=secrets.token_hex(4);pw="Aa9!"+secrets.token_urlsafe(19)
    us=[];tokens=[]
    for prefix in ["owner","member"]:
        username=prefix+sf
        st,r,_=call("POST","/users",{"username":username,"email":username+"@example.invalid","password":pw})
        need(st,201,"owned signup")
        us.append(r["id"]);tokens.append(login(username,pw))
    aid,bid=us;A,B=tokens
    st,t,_=call("POST","/teams",{"name":"wsrev"+sf,"display_name":"WS Revocation Test","type":"O"},A)
    need(st,201,"team");tid=t["id"]
    st,_,_=call("POST",f"/teams/{tid}/members",{"team_id":tid,"user_id":bid},A)
    need(st,201,"B team member")
    st,ch,_=call("POST","/channels",{"team_id":tid,"name":"private"+sf,"display_name":"Private Lab","type":"P"},A)
    need(st,201,"private channel");cid=ch["id"]
    st,_,_=call("POST",f"/channels/{cid}/members",{"user_id":bid},A)
    need(st,201,"B channel member")
    st,_,_=call("GET",f"/channels/{cid}/posts",token=B)
    chk("T01_B_can_read_before_removal",st==200,st,200)
    w=connect(B)
    try:
        before="WS_PRE_REVOKE_"+sf
        send(A,cid,before)
        frames=events(w,2.3)
        pos=sent_post(frames,before)
        chk("T02_B_WS_receives_private_post_while_member",pos>=1,pos,">=1")
        if pos<1:raise RuntimeError("no positive WS control, cannot interpret subsequent absence")
        st,_,_=call("DELETE",f"/channels/{cid}/members/{bid}",token=A)
        need(st,200,"A remove B from private")
        # Membership revocation must take effect before any subsequent post is created.
        st,_,_=call("GET",f"/channels/{cid}/posts",token=B)
        chk("T03_B_REST_denied_after_removal",st in (403,404),st,"403/404")
        immediate="WS_AFTER_REVOKE_NOW_"+sf
        send(A,cid,immediate)
        frames=events(w,2.3)
        exposed=sent_post(frames,immediate)
        removed_events=sum(1 for f in frames if f.get("event")=="user_removed")
        chk("T04_no_new_private_post_on_revoked_WS",exposed==0,
            {"leaked_private_posts":exposed,"user_removed_events":removed_events},
            "zero new private posts after confirmed REST revocation")
        st,_,_=call("GET",f"/posts/{send(A,cid,'WS_AFTER_REVOKE_LATER_'+sf)}",token=B)
        chk("T05_B_direct_post_GET_denied",st in (403,404),st,"403/404")
        delayed="WS_AFTER_REVOKE_FINAL_"+sf
        send(A,cid,delayed)
        frames=events(w,2.3)
        exposed2=sent_post(frames,delayed)
        chk("T06_no_delayed_private_post_on_revoked_WS",exposed2==0,exposed2,0)
    finally:
        w.close()
    print("RESULTS "+json.dumps({"iteration_enabled":os.getenv("WS_ITERATION")=="1","checks":OUT,
        "failures":[x["test"] for x in OUT if not x["pass"]]},sort_keys=True),flush=True)
    if any(not x["pass"] for x in OUT):sys.exit(2)
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("E2E_ERROR "+type(e).__name__+": "+str(e),flush=True);sys.exit(1)
