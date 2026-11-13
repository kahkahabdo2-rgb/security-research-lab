#!/usr/bin/env python3
"""Mattermost official 12.0.2: OAuth DCR trust-boundary micro-tests.
Only temporary clients on isolated CI. No user login / real callbacks.
"""
import json,os,urllib.request,urllib.error,secrets,sys
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
    print("RESULTS "+json.dumps({"mode":MODE,"failed":[x["name"] for x in RESULTS if not x["pass"]],
        "total":len(RESULTS)},sort_keys=True),flush=True)
    if any(not x["pass"] for x in RESULTS):sys.exit(2)
if __name__=="__main__":
    try:main()
    except Exception as e:
        print("E2E_ERROR "+type(e).__name__+" "+str(e),flush=True)
        sys.exit(1)
