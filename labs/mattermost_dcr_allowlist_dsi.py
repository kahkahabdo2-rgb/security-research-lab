#!/usr/bin/env python3
"""Mattermost official 12.0.2: OAuth DCR trust-boundary micro-tests.
Only disposable owned users and clients on isolated CI. No real callbacks.
"""
import json,os,urllib.request,urllib.error,urllib.parse,secrets,sys,hashlib,base64
BASE="http://127.0.0.1:8065"
MODE=os.environ.get("DCR_MODE","strict")
RESULTS=[]
def http(method,path,data=None):
    request=urllib.request.Request(BASE+path,data=json.dumps(data).encode() if data is not None else None,
         headers={"Content-Type":"application/json"},method=method)
    try:
        with urllib.request.urlopen(request,timeout=15) as r:
            status,raw=r.status,r.read()
    except urllib.error.HTTPError as e:
        status,raw=e.code,e.read()
    try: j=json.loads(raw.decode())
    except Exception:j={"unparsed":raw[:150].decode(errors="replace")}
    return status,j
def own_request(method,path,data=None,token=None,form=False):
    headers={"Content-Type":"application/x-www-form-urlencoded" if form else "application/json"}
    if token: headers["Authorization"]="Bearer "+token
    body=(urllib.parse.urlencode(data).encode() if form else json.dumps(data).encode()) if data is not None else None
    req=urllib.request.Request(BASE+path,data=body,headers=headers,method=method)
    try:
        with urllib.request.urlopen(req,timeout=15) as resp:
            status,payload,respHeaders=resp.status,resp.read(),resp.headers
    except urllib.error.HTTPError as e:
        status,payload,respHeaders=e.code,e.read(),e.headers
    try: result=json.loads(payload.decode()) if payload else {}
    except Exception: result={}
    return status,result,respHeaders
def token_exchange(client_id, code, verifier,redirect):
    return own_request("POST","/oauth/access_token",{
        "grant_type":"authorization_code","client_id":client_id,
        "redirect_uri":redirect,"code":code,"code_verifier":verifier
    },form=True)
def check(name,okay,observed,expected):
    v={"name":name,"pass":bool(okay),"observed":observed,"expected":expected}
    RESULTS.append(v)
    print("CHECK "+json.dumps(v,sort_keys=True),flush=True)
def register(uri,method="none",client_name=None,extra=None):
    body={"redirect_uris":uri if isinstance(uri,list) else [uri],
          "token_endpoint_auth_method":method,
          "client_name":client_name or ("dsi_lab_"+secrets.token_hex(4))}
    if extra:body.update(extra)
    return http("POST","/api/v4/oauth/apps/register",body)
def main():
    st,ping=http("GET","/api/v4/system/ping")
    if st!=200:raise ValueError("Native server not ready")
    trusted="https://approved.example.invalid/cb"
    if MODE=="disabled":
        status,out=register(trusted)
        check("C00_DCR_DISABLED",status==400 and out.get("error")=="unsupported_operation",
            {"status":status,"error":out.get("error")},"400 unsupported_operation")
    else:
        status,out=register(trusted)
        valid=status==201 and isinstance(out.get("client_id"),str)
        check("C00_DCR_ALLOWED_CONTROL",valid,{
           "status":status,"client_id_issued":bool(out.get("client_id")),
           "public_no_secret":out.get("client_secret") is None,
           "redirect_exact":out.get("redirect_uris")==[trusted]
        },"201 new public client with exact callback")
        if not valid:raise ValueError("Allowed control did not register; policy/env not validated")
        trusted_id=out["client_id"]
        # E2E rejection tests: bypasses of host, userinfo, path and multi-URI allowlists
        cases=[
          ("HOST_SUFFIX","https://approved.example.invalid.attacker.invalid/cb"),
          ("USERINFO_AUTHORITY","https://approved.example.invalid@attacker.invalid/cb"),
          ("HOST_DOT_OMISSION","https://approved-example.invalid/cb"),
          ("ENCODED_PATH_TRAVERSAL","https://approved.example.invalid/cb/%2e%2e/else"),
          ("PATH_PREFIX_CONFUSION","https://approved.example.invalid/cb-extra"),
          ("QUERY_REDIRECT","https://approved.example.invalid/cb?next=https://attacker.invalid/"),
          ("FRAGMENT_CONFUSION","https://approved.example.invalid/cb#@attacker.invalid"),
          ("SCHEME_CONFUSION","http://approved.example.invalid/cb"),
          ("DEFAULT_PORT_VARIANT","https://approved.example.invalid:443/cb")
        ]
        for key,uri in cases:
            status,out=register(uri)
            check("C_"+key,status==400,{
              "status":status,"error":out.get("error"),"issued_client_id":bool(out.get("client_id"))
            },"400 no OAuth client created")
        status,out=register([trusted,"https://attacker.invalid/cb"])
        check("C_MULTI_REDIRECT_PARTIAL_ALLOWLIST",status==400,{"status":status,
           "error":out.get("error"),"issued_client_id":bool(out.get("client_id"))},
           "400 entire registration rejected")
        st,info=http("GET","/api/v4/oauth/apps/"+out.get("client_id","none"))
        check("C_NO_UNAUTH_APP_READ",st in (401,403,404),{"status":st},"401/403/404")
        status,out=register(trusted,"client_secret_basic")
        check("C_UNSUPPORTED_AUTH_METHOD",status==400,
            {"status":status,"error":out.get("error")},"400")
        # Cross-component flow: DCR -> OAuth consent -> authorization code -> PKCE -> session.
        # These are two test-owned users. The first may be bootstrap sysadmin,
        # so the second is always the non-admin user for the OAuth authorization.
        owned=[]
        password="Aa9!"+secrets.token_urlsafe(20)
        for i in (1,2):
            username="dcr"+str(i)+secrets.token_hex(5)
            status,user,_=own_request("POST","/api/v4/users",{
               "username":username,"email":username+"@example.invalid","password":password
            })
            if status!=201:raise RuntimeError("creating disposable user failed "+str(status))
            owned.append((username,user["id"]))
        user_name,user_id=owned[-1]
        status,_,hdr=own_request("POST","/api/v4/users/login",{
           "login_id":user_name,"password":password
        })
        if status!=200 or not hdr.get("Token"):raise RuntimeError("owned user login failed")
        own_token=hdr["Token"]  # NEVER printed to CI log
        status,me,_=own_request("GET","/api/v4/users/me",token=own_token)
        check("C_OWNED_ORDINARY_USER_CONTROL",status==200 and me.get("id")==user_id,
              {"http":status,"is_expected_user":me.get("id")==user_id},"test user authenticated")

        # Two registered public clients bound to the SAME approved callback.
        # Attacker client B must never exchange client A's authorization code.
        status,client2=register(trusted,"none")
        if status!=201:raise RuntimeError("Cannot create owned cross-client negative control")
        # Public client A identifier from earlier trusted DCR positive.
        # First approved registration stored before the rejection matrix.
        pub_a=trusted_id
        pub_b=client2["client_id"]
        verifier=secrets.token_urlsafe(50)
        challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        baseauth={"response_type":"code","client_id":pub_a,
            "redirect_uri":trusted,"scope":"user","state":"owned-dsi-state",
            "code_challenge":challenge,"code_challenge_method":"S256"}

        status,no_pkce,_=own_request("POST","/oauth/authorize",{
            k:v for k,v in baseauth.items() if k not in ("code_challenge","code_challenge_method")
        },token=own_token)
        check("C_PUBLIC_CODE_WITHOUT_PKCE_DENIED",status==400,{"http":status},"400")

        status,bad_redirect,_=own_request("POST","/oauth/authorize",{
            **baseauth,"redirect_uri":"https://attacker.invalid/cb"
        },token=own_token)
        check("C_OAUTH_GRANT_TO_UNREGISTERED_REDIRECT_DENIED",status==400,
              {"http":status},"400")

        status,authorized,_=own_request("POST","/oauth/authorize",baseauth,token=own_token)
        redirect=authorized.get("redirect","")
        query=urllib.parse.parse_qs(urllib.parse.urlparse(redirect).query)
        code=query.get("code",[""])[0]
        check("C_OWNED_AUTHORIZATION_CODE_POSITIVE",status==200 and bool(code),
              {"http":status,"has_code":bool(code),"code_not_exposed":True},"200 code bound to client A")
        if status!=200 or not code:raise RuntimeError("No positive authorization code")

        status,denied,_=token_exchange(pub_b,code,verifier,trusted)
        check("C_CROSS_CLIENT_CODE_EXCHANGE_DENIED",status in (400,401,403),
              {"http":status,"access_token_issued":bool(denied.get("access_token"))},
              "no token for client B")
        status,denied,_=token_exchange(pub_a,code,"mismatched"+verifier,trusted)
        check("C_WRONG_PKCE_VERIFIER_DENIED",status in (400,401,403),
              {"http":status,"access_token_issued":bool(denied.get("access_token"))},
              "no token with incorrect verifier")
        status,grant,_=token_exchange(pub_a,code,verifier,trusted)
        access=grant.get("access_token","")
        check("C_CORRECT_PKCE_POSITIVE",status==200 and bool(access),
              {"http":status,"access_token_issued":bool(access),
               "refresh_token_absent":not bool(grant.get("refresh_token"))},
              "own user OAuth access token, no refresh token")
        if status!=200 or not access:raise RuntimeError("Cannot test session isolation without OAuth grant")
        status,replay,_=token_exchange(pub_a,code,verifier,trusted)
        check("C_AUTH_CODE_REPLAY_DENIED",status in (400,401,403),
              {"http":status,"token_issued":bool(replay.get("access_token"))},
              "one-time authorization code")
        status,read,_=own_request("GET","/api/v4/users/me",token=access)
        check("C_OAUTH_GRANTED_TOKEN_BELONGS_TO_OWNER",status==200 and read.get("id")==user_id,
              {"http":status,"right_owned_user":read.get("id")==user_id},
              "access token bound to authorizing test user")
        status,chain,_=own_request("POST","/oauth/authorize",{
           **baseauth,"client_id":pub_b
        },token=access)
        check("C_OAUTH_TOKEN_CANNOT_AUTHORIZE_FURTHER_OAUTH_CLIENT",status in (400,401,403),
              {"http":status,"returned_code":bool(chain.get("redirect"))},
              "OAuth sessions cannot initiate another OAuth grant")

    print("RESULTS "+json.dumps({"mode":MODE,"failed":[x["name"] for x in RESULTS if not x["pass"]],
        "total":len(RESULTS)},sort_keys=True),flush=True)
    if any(not x["pass"] for x in RESULTS):sys.exit(2)
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("E2E_ERROR "+type(e).__name__+" "+str(e),flush=True)
        sys.exit(1)
