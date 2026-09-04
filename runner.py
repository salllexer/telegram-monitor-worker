import base64, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request, uuid

WORKER = os.environ["WORKER_URL"].strip().rstrip("/")
SECRET = os.environ["RUNNER_SECRET"].strip()
if not WORKER.startswith(("https://", "http://")):
    raise RuntimeError("WORKER_URL must start with https://")
if "/telegram/webhook" in WORKER or "/runner/" in WORKER:
    raise RuntimeError("WORKER_URL must be the Worker root URL only, without /telegram/webhook or /runner/due")

def b64(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()

def vless(uri):
    u=urllib.parse.urlparse(uri); q=urllib.parse.parse_qs(u.query); p={k:v[0] for k,v in q.items()}
    stream={"network":p.get("type","tcp")}
    net=stream["network"]
    if net=="ws": stream["wsSettings"]={"path":p.get("path","/"),"headers":({"Host":p["host"]} if p.get("host") else {})}
    if net=="grpc": stream["grpcSettings"]={"serviceName":p.get("serviceName","")}
    security=p.get("security","none"); stream["security"] = security
    if security=="reality": stream["realitySettings"]={"serverName":p.get("sni",p.get("host",u.hostname)),"fingerprint":p.get("fp","chrome"),"publicKey":p.get("pbk","") ,"shortId":p.get("sid","")}
    elif security=="tls": stream["tlsSettings"]={"serverName":p.get("sni",p.get("host",u.hostname)),"allowInsecure":p.get("allowInsecure","0")=="1"}
    return {"protocol":"vless","settings":{"vnext":[{"address":u.hostname,"port":u.port or 443,"users":[{"id":u.username,"encryption":p.get("encryption","none"),"flow":p.get("flow","")}]}]},"streamSettings":stream,"tag":"proxy"}

def vmess(uri):
    raw=uri.split("//",1)[1].split("#",1)[0]; d=json.loads(b64(raw)); q=d
    stream={"network":q.get("net","tcp")}; net=stream["network"]
    if net=="ws": stream["wsSettings"]={"path":q.get("path","/"),"headers":({"Host":q["host"]} if q.get("host") else {})}
    if net=="grpc": stream["grpcSettings"]={"serviceName":q.get("path","")}
    sec=q.get("tls","none"); stream["security"]="tls" if sec else "none"
    if sec: stream["tlsSettings"]={"serverName":q.get("sni",q.get("host",q.get("add"))),"allowInsecure":True}
    return {"protocol":"vmess","settings":{"vnext":[{"address":q["add"],"port":int(q.get("port",443)),"users":[{"id":q["id"],"alterId":int(q.get("aid",0)),"security":q.get("scy","auto")}]}]},"streamSettings":stream,"tag":"proxy"}

def trojan(uri):
    u=urllib.parse.urlparse(uri); q=urllib.parse.parse_qs(u.query); p={k:v[0] for k,v in q.items()}; stream={"network":p.get("type","tcp"),"security":p.get("security","tls")}
    if stream["network"]=="ws": stream["wsSettings"]={"path":p.get("path","/"),"headers":({"Host":p["host"]} if p.get("host") else {})}
    stream["tlsSettings"]={"serverName":p.get("sni",u.hostname),"allowInsecure":p.get("allowInsecure","0")=="1"}
    return {"protocol":"trojan","settings":{"servers":[{"address":u.hostname,"port":u.port or 443,"password":urllib.parse.unquote(u.username)}]},"streamSettings":stream,"tag":"proxy"}

def shadowsocks(uri):
    x=uri.split("#",1)[0]; body=x.split("//",1)[1]; body=body.split("@",1)
    if len(body)==2: user,host=body; user=b64(user)
    else: user=body[0]; host=body[1] if len(body)>1 else ""
    method,password=user.split(":",1); h,p=host.rsplit(":",1)
    return {"protocol":"shadowsocks","settings":{"servers":[{"address":h,"port":int(p),"method":method,"password":password}]},"tag":"proxy"}

def make_config(raw, port):
    raw=raw.strip()
    if raw.startswith("vless://"): outbound=vless(raw)
    elif raw.startswith("vmess://"): outbound=vmess(raw)
    elif raw.startswith("trojan://"): outbound=trojan(raw)
    elif raw.startswith("ss://"): outbound=shadowsocks(raw)
    elif raw.startswith("{"):
        c=json.loads(raw)
        if "outbounds" not in c: raise ValueError("JSON فاقد outbounds است")
        if not any(o.get("tag")=="proxy" for o in c["outbounds"]): c["outbounds"][0]["tag"]="proxy"
        c.setdefault("inbounds",[]).append({"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":True},"tag":"local"})
        return c
    else: raise ValueError("فرمت پشتیبانی‌نشده")
    return {"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks","settings":{"udp":True},"tag":"local"}],"outbounds":[outbound,{"protocol":"freedom","tag":"direct"}]}

def post_result(cid, ok, ping=None, error=None):
    data=json.dumps({"id":cid,"ok":ok,"ping_ms":ping,"error":error}).encode()
    req=urllib.request.Request(WORKER+"/runner/result",data=data,headers={"Authorization":"Bearer "+SECRET,"Content-Type":"application/json","User-Agent":"Mozilla/5.0 (compatible; ConfigMonitor/1.0; +https://github.com)"})
    try:
        with urllib.request.urlopen(req,timeout=20) as r: r.read()
    except Exception as e: print("result post failed",e,file=sys.stderr)

def main():
    req=urllib.request.Request(WORKER+"/runner/due",headers={"Authorization":"Bearer "+SECRET,"User-Agent":"Mozilla/5.0 (compatible; ConfigMonitor/1.0; +https://github.com)"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            items = json.load(r).get("configs", [])
            print("Worker /runner/due status:", r.status)
            print("Due configurations:", len(items))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print("Worker /runner/due HTTP status:", e.code, file=sys.stderr)
        print("Worker response body:", body, file=sys.stderr)
        print("Check WORKER_URL and RUNNER_SECRET in GitHub Actions.", file=sys.stderr)
        raise
    except urllib.error.URLError as e:
        print("Could not reach Worker:", e.reason, file=sys.stderr)
        print("Check WORKER_URL and the Worker deployment.", file=sys.stderr)
        raise
    for c in items:
        port=18000+(int(uuid.uuid4().int)%1000); started=time.monotonic(); proc=None
        try:
            cfg=make_config(c["raw"],port)
            with tempfile.TemporaryDirectory() as td:
                path=os.path.join(td,"config.json"); open(path,"w",encoding="utf8").write(json.dumps(cfg,ensure_ascii=False))
                proc=subprocess.Popen(["./xray","run","-c",path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                time.sleep(2)
                curl=subprocess.run(["curl","--silent","--show-error","--fail","--max-time","15","--socks5-hostname",f"127.0.0.1:{port}","-o","/dev/null","-w","%{http_code}",c.get("test_url") or "https://www.google.com/generate_204"],capture_output=True,text=True)
                ms=round((time.monotonic()-started)*1000)
                if curl.returncode!=0: raise RuntimeError(curl.stderr.strip() or "request failed")
                code=int(curl.stdout or 0)
                if code<200 or code>=400: raise RuntimeError("HTTP "+str(code))
                post_result(c["id"],True,ms,None); print(c["id"],"UP",ms)
        except Exception as e: post_result(c["id"],False,None,str(e)[:300]); print(c["id"],"DOWN",e)
        finally:
            if proc: proc.terminate(); proc.wait(timeout=3)
if __name__=="__main__": main()
