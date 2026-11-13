#!/usr/bin/env python3
"""Mattermost 12.0.2 official: Discoverable private channel join-request DSI.
Disposable CI users/teams only; no real credentials, no scanning.
"""
import json, secrets, sys, time, urllib.request, urllib.error
import websocket

API="http://127.0.0.1:8065/api/v4"
RESULTS=[]
def check(name,ok,observed,expected):
    d={"test":name,"pass":bool(ok),"observed":observed,"expected":expected}
    RESULTS.append(d)
    print("CHECK "+json.dumps(d,sort_keys=True),flush=True)

def request(method,path,payload=None,token=None):
    headers={"Content-Type":"application/json"}
    if token: headers["Authorization"]="Bearer "+token
    body=json.dumps(payload).encode() if payload is not None else None
    req=urllib.request.Request(API+path,headers=headers,data=body,method=method)
    try:
        with urllib.request.urlopen(req,timeout=25) as resp: status=resp.status;raw=resp.read();h=resp.headers
    except urllib.error.HTTPError as e: status=e.code;raw=e.read();h=e.headers
    try: data=json.loads(raw.decode()) if raw else None
    except Exception: data={"unparsed":raw[:240].decode(errors="replace")}
    return status,data,h

def expected(status,code,what):
    if status!=code: raise RuntimeError(f"{what}: expected {code}, got {status}")

def login(user,pw):
    st,_,h=request("POST","/users/login",{"login_id":user,"password":pw})
    expected(st,200,"login")
    if not h.get("Token"): raise RuntimeError("login returned no token")
    return h["Token"]

def ws_auth(token):
    w=websocket.create_connection("ws://127.0.0.1:8065/api/v4/websocket",timeout=6)
    w.send(json.dumps({"seq":1,"action":"authentication_challenge","data":{"token":token}}))
    limit=time.monotonic()+7
    while time.monotonic()<limit:
        try: frame=json.loads(w.recv())
        except websocket.WebSocketTimeoutException: continue
        if frame.get("seq_reply")==1:
            if frame.get("status")!="OK":raise RuntimeError("WS auth failed")
            w.settimeout(.20)
            return w
    raise RuntimeError("WS auth timed out")

def received(ws,event,canary,seconds=2.0):
    cnt=0;end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            frame=json.loads(ws.recv())
            if frame.get("event")==event and canary in json.dumps(frame): cnt+=1
        except websocket.WebSocketTimeoutException: pass
    return cnt

def main():
    st,_,_=request("GET","/system/ping")
    expected(st,200,"ping")
    suffix=secrets.token_hex(4)
    pwd="Aa9!"+secrets.token_urlsafe(22)
    usernames=["jr_a_"+suffix,"jr_b_"+suffix,"jr_c_"+suffix]
    ids=[];tokens=[]
    for u in usernames:
        st,data,_=request("POST","/users",{"username":u,"email":u+"@example.invalid","password":pwd})
        expected(st,201,"test user signup")
        ids.append(data["id"])
    for u in usernames: tokens.append(login(u,pwd))
    A,B,C=tokens;aid,bid,cid=ids
    st,t1,_=request("POST","/teams",{"name":"jrteam1"+suffix,"display_name":"JR Invite-Only Team","type":"I"},A)
    expected(st,201,"team1 create")
    st,t2,_=request("POST","/teams",{"name":"jrteam2"+suffix,"display_name":"JR Team Two","type":"O"},A)
    expected(st,201,"team2 create")
    t1id=t1["id"];t2id=t2["id"]
    st,_,_=request("POST",f"/teams/{t2id}/members",{"team_id":t2id,"user_id":bid},A)
    expected(st,201,"B in other team")
    st,_,_=request("POST",f"/teams/{t1id}/members",{"team_id":t1id,"user_id":cid},A)
    expected(st,201,"C in team1")
    private_header="DSI_PRIVATE_HEADER_"+suffix
    private_purpose="DSI_PRIVATE_PURPOSE_"+suffix
    cname="jrp"+suffix
    st,ch,_=request("POST","/channels",{"team_id":t1id,"name":cname,
        "display_name":"Private Discoverable","type":"P","discoverable":True,
        "header":private_header,"purpose":private_purpose},A)
    expected(st,201,"create discoverable private channel")
    chid=ch["id"]
    print("CONFIG "+json.dumps({"channel_discoverable":ch.get("discoverable"),"private":ch.get("type")=="P"}),flush=True)
    st,missing_member,_=request("GET",f"/teams/{t1id}/members/{bid}",token=A)
    check("T00_outsider_has_no_membership_in_invite_only_team",
          st in (403,404),{"http":st,"member_data":isinstance(missing_member,dict) and "user_id" in missing_member},
          "B is not on invite-only team")
    st,team_view,_=request("GET",f"/teams/{t1id}",token=B)
    check("T00_outsider_team_lookup",True,{"http":st,
          "team_name_visible":isinstance(team_view,dict) and team_view.get("name")=="jrteam1"+suffix},
          "record whether invite-only team metadata is hidden")
    st,team_channels,_=request("GET",f"/teams/{t1id}/channels",token=B)
    check("T00_outsider_team_channel_listing_denied",st in (403,404),st,"403/404")
    st,anon_view,_=request("GET",f"/channels/{chid}")
    check("T00_anonymous_private_channel_denied",anon_view is None or st in (401,403,404),st,"401/403/404")
        st,adminview,_=request("GET",f"/channels/{chid}",token=A)
    check("T00_admin_private_metadata_control",st==200 and adminview.get("header")==private_header and adminview.get("purpose")==private_purpose,
          {"http":st,"header_canary":adminview.get("header")==private_header,"purpose_canary":adminview.get("purpose")==private_purpose},"admin sees own channel metadata")
    st,from_other_team,_=request("GET",f"/channels/{chid}",token=B)
    exposed_by_id=st==200 and isinstance(from_other_team,dict) and from_other_team.get("header")==private_header and from_other_team.get("purpose")==private_purpose
    check("T00_cross_team_private_metadata_direct_id",True,
          {"http":st,"metadata_exposed":exposed_by_id,
           "has_props":isinstance(from_other_team,dict) and from_other_team.get("props") is not None},
          "record cross-team disclosure; metadata_exposed=true is suspicious")
    st,by_teamid,_=request("GET",f"/teams/{t1id}/channels/name/{cname}",token=B)
    exposed_by_teamid=st==200 and isinstance(by_teamid,dict) and by_teamid.get("header")==private_header and by_teamid.get("purpose")==private_purpose
    check("T00_cross_team_private_metadata_by_team_id_and_name",True,
          {"http":st,"metadata_exposed":exposed_by_teamid},
          "record exposure without direct channel id")
    st,by_teamname,_=request("GET",f"/teams/name/jrteam1{suffix}/channels/name/{cname}",token=B)
    exposed_by_teamname=st==200 and isinstance(by_teamname,dict) and by_teamname.get("header")==private_header and by_teamname.get("purpose")==private_purpose
    check("T00_cross_team_private_metadata_by_team_name_and_channel_name",True,
          {"http":st,"metadata_exposed":exposed_by_teamname},
          "record exposure using guessable names")
    st,team_nonmember,_=request("GET",f"/channels/{chid}",token=C)
    check("T00_same_team_nonmember_intended_metadata",st==200 and team_nonmember.get("header")==private_header,
          {"http":st,"header_canary":isinstance(team_nonmember,dict) and team_nonmember.get("header")==private_header},
          "same-team member can discover metadata")
    st,hidden,_=request("POST","/channels",{"team_id":t1id,"name":"jrh"+suffix,
        "display_name":"Private Hidden","type":"P","discoverable":False,
        "header":"DSI_HIDDEN_HEADER_"+suffix},A)
    expected(st,201,"create hidden private negative control")
    st,hidden_data,_=request("GET",f"/channels/{hidden['id']}",token=B)
    check("T00_nondiscoverable_cross_team_metadata_denied",st in (403,404),
          {"http":st,"hidden_header_visible":isinstance(hidden_data,dict) and hidden_data.get("header")=="DSI_HIDDEN_HEADER_"+suffix},
          "403/404, no metadata")
    st,_,_=request("POST",f"/channels/{chid}/members",{"user_id":cid},A)
    expected(st,201,"C normal private-channel member")
    st,_,_=request("POST",f"/posts",{"channel_id":chid,"message":"PRIVATE_TEST_"+suffix},B)
    check("T00_unauthorized_private_post_control",st in (403,404),st,"403/404")
    wa=ws_auth(A);wc=ws_auth(C);wb=ws_auth(B)
    try:
        canary="JOIN_REQUEST_SENTINEL_"+suffix
        st,req,_=request("POST",f"/channels/{chid}/join_request",{"message":canary},B)
        check("T01_cross_team_join_request",st==201 and isinstance(req,dict) and req.get("status")=="pending",
              {"status":st,"state":req.get("status") if isinstance(req,dict) else None},
              "Record if out-of-team request is accepted")
        if st!=201 or not isinstance(req,dict) or not req.get("id"):raise RuntimeError("join request unavailable")
        rid=req["id"]
        ahit=received(wa,"channel_join_request_created",canary,2.4)
        chit=received(wc,"channel_join_request_created",canary,2.4)
        check("T02_admin_WS_positive",ahit>=1,ahit,">=1")
        check("T03_nonadmin_channel_member_WS_isolated",chit==0,chit,0)
        st,data,_=request("GET",f"/channels/{chid}/join_requests",token=A)
        visible=st==200 and rid in json.dumps(data)
        check("T04_admin_list_positive",visible,{"http":st,"request_present":visible},"200 with request")
        st,_,_=request("GET",f"/channels/{chid}/join_requests",token=C)
        check("T05_nonadmin_channel_member_list_denied",st in (403,404),st,"403/404")
        st,_,_=request("PATCH",f"/channels/{chid}/join_requests/{rid}",{"status":"approved"},C)
        check("T06_nonadmin_approval_denied",st in (403,404),st,"403/404")
        # A is authorized reviewer but B is not a member of channel's team.
        st,_,_=request("PATCH",f"/channels/{chid}/join_requests/{rid}",{"status":"approved"},A)
        check("T07_approval_for_external_team_denied",st in (400,403,404),st,"400/403/404")
        st,_,_=request("GET",f"/channels/{chid}/members/{bid}",token=A)
        check("T08_cross_team_channel_membership_not_created",st in (403,404),st,"403/404")
        st,withdrawn,_=request("DELETE",f"/channels/{chid}/join_request",token=B)
        check("T09_withdraw_own_request",st==200 and withdrawn.get("status")=="withdrawn",
              {"http":st,"state":withdrawn.get("status") if isinstance(withdrawn,dict) else None},"200 withdrawn")
        st,_,_=request("PATCH",f"/channels/{chid}/join_requests/{rid}",{"status":"approved"},A)
        check("T10_approval_after_withdraw_denied",st==409,st,409)
        # B now belongs to team1. Create another request then revoke team before review.
        st,_,_=request("POST",f"/teams/{t1id}/members",{"team_id":t1id,"user_id":bid},A)
        expected(st,201,"add B to team1")
        st,req2,_=request("POST",f"/channels/{chid}/join_request",{"message":"PENDING_BEFORE_REVOCATION_"+suffix},B)
        expected(st,201,"create pending before team revocation")
        rid2=req2["id"]
        st,_,_=request("DELETE",f"/teams/{t1id}/members/{bid}",token=A)
        expected(st,200,"remove B from team1")
        st,_,_=request("PATCH",f"/channels/{chid}/join_requests/{rid2}",{"status":"approved"},A)
        check("T11_admin_approval_after_team_revocation_denied",st in (400,403,404),st,"400/403/404")
        st,_,_=request("GET",f"/channels/{chid}/members/{bid}",token=A)
        check("T12_no_membership_after_revoked_approval",st in (403,404),st,"403/404")
        # Positive path: restore team membership; review the same pending request.
        st,_,_=request("POST",f"/teams/{t1id}/members",{"team_id":t1id,"user_id":bid},A)
        expected(st,201,"restore B team membership")
        st,approved,_=request("PATCH",f"/channels/{chid}/join_requests/{rid2}",{"status":"approved"},A)
        check("T13_authorized_approval_after_restore",st==200 and approved.get("status")=="approved",
              {"http":st,"state":approved.get("status") if isinstance(approved,dict) else None},"200 approved")
        st,_,_=request("GET",f"/channels/{chid}/members/{bid}",token=A)
        check("T14_authorized_membership_positive",st==200,st,200)
        st,_,_=request("POST","/posts",{"channel_id":chid,"message":"AUTHORIZED_TEST_"+suffix},B)
        check("T15_authorized_post_positive",st==201,st,201)
    finally:
        for w in (wa,wc,wb):
            try: w.close()
            except Exception: pass
    print("RESULTS "+json.dumps({"version":"mattermost-team-edition:12.0.2",
         "failed_checks":[x["test"] for x in RESULTS if not x["pass"]],
         "checks":RESULTS},sort_keys=True),flush=True)
    if any(not x["pass"] for x in RESULTS):sys.exit(2)

if __name__=="__main__":
    try:main()
    except Exception as e:
        print("E2E_ERROR "+type(e).__name__+" "+str(e),flush=True);sys.exit(1)
