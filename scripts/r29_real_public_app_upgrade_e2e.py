#!/usr/bin/env python3
"""R29: public-source FastAPI + real Celery worker + Redis + PostgreSQL 16/17.

UNTRUSTED THIRD-PARTY CODE EXECUTED ONLY IN PRIVATE DISPOSABLE CONTAINERS.
The test harness is Python; Tredven's trusted policy/decision logic remains Rust.
DISPOSABLE/TEST-ONLY. Zero existing user DBs, no host ports, rootless Podman.
Private local test evidence only; DOES NOT create an attestation or approve rollout.
"""
from __future__ import annotations
import argparse, hashlib, json, os, pathlib, re, subprocess, sys, time, uuid
from datetime import datetime, timezone

REPO=pathlib.Path(__file__).resolve().parent.parent
OUTROOT=REPO/"output/r29-public-app-fixture"
SOURCE=OUTROOT/"upstream-paul"
PIN="417de5b4c3e2741853944fbf97a9988de48d647d"
APP="localhost/tredven-r29-public-fastapi-worker-redis:417de5b"
DB16="docker.io/library/postgres:16"
DB17="docker.io/library/postgres:17"
BROKER="docker.io/library/redis:7-alpine"
PREFIX="tredven-r29-isolated-"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def run(*args, check=True, timeout=50, input=None):
    p=subprocess.run(list(args),stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                    input=input,timeout=timeout)
    if check and p.returncode!=0:
        raise RuntimeError("SUBPROCESS_FAILED "+str(args[:4])+" "+p.stderr.decode(errors="replace")[-600:])
    return p
def p(*args, check=True, timeout=60, input=None):
    return run("podman",*args,check=check,timeout=timeout,input=input)
def out(p): return p.stdout.decode("utf-8").strip()
def cmd_git(repo,*args):
    env={**os.environ,"GIT_CONFIG_NOSYSTEM":"1","GIT_CONFIG_GLOBAL":"/dev/null",
         "GIT_TERMINAL_PROMPT":"0"}
    r=subprocess.run(["git","-C",str(repo),*args],env=env,
                     capture_output=True,text=True,timeout=20,check=True)
    return r.stdout.strip()
def imageid(image):
    return out(p("image","inspect",image,"--format","{{.Id}}"))
def check_preconditions():
    if os.geteuid()==0: raise RuntimeError("ROOT_FORBIDDEN")
    if out(p("info","--format","{{.Host.Security.Rootless}}"))!="true":
        raise RuntimeError("PODMAN_MUST_BE_ROOTLESS")
    if cmd_git(SOURCE,"rev-parse","HEAD")!=PIN:
        raise RuntimeError("UPSTREAM_SOURCE_COMMIT_DRIFT")
    if cmd_git(SOURCE,"status","--porcelain")!="":
        raise RuntimeError("UPSTREAM_SOURCE_DIRTY")
    return {i:imageid(i) for i in (APP,DB16,DB17,BROKER)}

class Sandbox:
    def __init__(self,output):
        self.output=output
        self.suffix=uuid.uuid4().hex[:12]
        self.network=PREFIX+"net-"+self.suffix
        self.dbvol_old=PREFIX+"oldpg-"+self.suffix
        self.dbvol_new=PREFIX+"newpg-"+self.suffix
        self.broker=PREFIX+"broker-"+self.suffix
        self.db_old=PREFIX+"db16-"+self.suffix
        self.db_new=PREFIX+"db17-"+self.suffix
        self.api_old=PREFIX+"api16-"+self.suffix
        self.worker_old=PREFIX+"worker16-"+self.suffix
        self.api_new=PREFIX+"api17-"+self.suffix
        self.worker_new=PREFIX+"worker17-"+self.suffix
        self.names=[];self.volumes=[];self.network_created=False

    def setup(self):
        p("network","create","--internal","--label","tredven-r29=isolated",self.network)
        self.network_created=True
        for name in (self.dbvol_old,self.dbvol_new):
            p("volume","create","--label","tredven-r29=isolated",name)
            self.volumes.append(name)
        self.launch(self.broker,BROKER,alias="broker")
        self.wait_broker()

    def launch(self,name,image,*arguments,alias=None,command=()):
        assert name.startswith(PREFIX)
        args=["run","-d","--pull=never","--name",name,
              "--network",self.network,"--security-opt=no-new-privileges",
              "--pids-limit","256"]
        if alias:args.extend(["--network-alias",alias])
        args.extend(arguments);args.append(image);args.extend(command)
        response=p(*args,timeout=50)
        self.names.append(name)
        return out(response)

    def wait_broker(self):
        start=time.monotonic()
        while time.monotonic()-start<45:
            x=p("exec",self.broker,"redis-cli","PING",check=False,timeout=10)
            if x.returncode==0 and out(x)=="PONG":return
            time.sleep(.7)
        raise RuntimeError("BROKER_NOT_READY")

    def db(self,image,old):
        name=self.db_old if old else self.db_new
        volume=self.dbvol_old if old else self.dbvol_new
        self.launch(name,image,
            "-v",volume+":/var/lib/postgresql/data",
            "-e","POSTGRES_HOST_AUTH_METHOD=trust",
            "-e","POSTGRES_DB=appdb",alias="db")
        t=time.monotonic()
        while time.monotonic()-t<40:
            x=p("exec",name,"pg_isready","-h","127.0.0.1",
                "-U","postgres","-d","appdb",check=False,timeout=9)
            if x.returncode==0:return name
            time.sleep(.5)
        raise RuntimeError("DB_TCP_READY_TIMEOUT")

    def env_vars(self):
        dsn="postgresql://postgres@db:5432/appdb"
        broker="redis://broker:6379/0"
        return ["-e","DATABASE_URL=postgresql+asyncpg://postgres@db:5432/appdb",
                "-e","DATABASE_URL_SYNC=postgresql+psycopg2://postgres@db:5432/appdb",
                "-e","RABBITMQ_URL="+broker,
                "-e","CELERY_BROKER_URL="+broker,
                "-e","CELERY_RESULT_BACKEND=redis://broker:6379/1",
                "-e","APP_NAME=R29 isolated public-source app",
                "-e","DEBUG=false"]

    def app(self,old):
        api=self.api_old if old else self.api_new
        worker=self.worker_old if old else self.worker_new
        opts=self.env_vars()
        self.launch(worker,APP,*opts,alias="worker",command=(
            "-m","celery","-A","app.celery_app","worker",
            "--loglevel=warning","--pool=solo","--concurrency=1"))
        self.launch(api,APP,*opts,alias="api",command=(
            "-m","uvicorn","app.main:app","--host","0.0.0.0","--port","8000"))
        t=time.monotonic()
        while time.monotonic()-t<55:
            r=p("exec",api,"python","-c",
                "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health',timeout=4).read().decode())",
                check=False,timeout=12)
            if r.returncode==0 and "healthy" in out(r):
                return api,worker
            x=p("inspect",api,"--format","{{.State.Status}}",check=False)
            if x.returncode or out(x)!="running": raise RuntimeError("API_PROCESS_STOPPED")
            time.sleep(.5)
        raise RuntimeError("API_NOT_READY")

    def http(self,method,path,payload=None):
        # Separate real client container, not a direct Python FastAPI test helper.
        python=('import sys,json,urllib.request;'
                'body=json.loads(sys.argv[3]) if sys.argv[3]!="null" else None;'
                'data=json.dumps(body).encode() if body is not None else None;'
                'r=urllib.request.Request("http://api:8000"+sys.argv[2],data=data,method=sys.argv[1],'
                'headers={"Content-Type":"application/json"});'
                'print(urllib.request.urlopen(r,timeout=8).read().decode())')
        body=json.dumps(payload) if payload is not None else "null"
        r=p("run","--rm","--pull=never","--network",self.network,
            "--security-opt=no-new-privileges","--pids-limit","64",
            "--entrypoint","python",APP,"-c",python,method,path,body,timeout=40)
        return json.loads(out(r))

    def sql(self,db,statement):
        r=p("exec","--user","postgres",db,
            "psql","-U","postgres","-d","appdb","-At",
            "-v","ON_ERROR_STOP=1","-c",statement,timeout=30)
        return out(r)

    def wait_task(self,content,seconds=55):
        t=time.monotonic()
        while time.monotonic()-t<seconds:
            messages=self.http("GET","/messages/")
            matches=[m for m in messages if m["content"]==content]
            if matches:return matches[-1]
            time.sleep(1.2)
        raise RuntimeError("WORKER_DID_NOT_PERSIST_TASK:"+content)

    def verify_apps(self,stage):
        direct="r29-"+stage+"-direct"
        queued="r29-"+stage+"-queued"
        r=self.http("POST","/messages/",{"content":direct})
        assert r["content"]==direct
        enqueued=self.http("POST","/tasks/",{"content":queued})
        assert enqueued.get("task_id")
        processed=self.wait_task(queued)
        assert processed["content"]==queued
        count=int(self.sql(self.db_old if stage=="baseline" else self.db_new,
                           "SELECT count(*) FROM messages;"))
        if count<2:raise RuntimeError("APP_MESSAGE_COUNT_TOO_LOW")
        return {"stage":stage,"direct_id":r["id"],"worker_task_id":enqueued["task_id"],
                "worker_persisted_id":processed["id"],"row_count":count}

    def drop(self,name):
        if name not in self.names:raise RuntimeError("UNKNOWN_TEST_CONTAINER_DROP")
        p("rm","-f",name,timeout=30)
        self.names.remove(name)

    def shutdown_app(self,old):
        for name in ([self.api_old,self.worker_old] if old else [self.api_new,self.worker_new]):
            self.drop(name)

    def cleanup(self):
        errors=[]
        for name in reversed(self.names):
            # Capture *only* this disposable container's own logs before removal.
            # Private evidence directory, bounded bytes, no existing service logs.
            if name.startswith(PREFIX) and self.output.is_dir():
                raw=p("logs",name,check=False,timeout=15)
                contents=(raw.stdout+raw.stderr)[-30000:]
                logfile=self.output/("log-"+name+".txt")
                with os.fdopen(os.open(logfile,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as dest:
                    dest.write(contents)
            if p("rm","-f",name,check=False,timeout=30).returncode:
                errors.append(("container",name))
        for v in reversed(self.volumes):
            if p("volume","rm","-f",v,check=False,timeout=30).returncode:
                errors.append(("volume",v))
        if self.network_created:
            if p("network","rm",self.network,check=False,timeout=30).returncode:
                errors.append(("network",self.network))
        for n in self.names:
            if p("container","exists",n,check=False).returncode==0:errors.append(("left_container",n))
        for v in self.volumes:
            if p("volume","exists",v,check=False).returncode==0:errors.append(("left_volume",v))
        if self.network_created:
            if p("network","exists",self.network,check=False).returncode==0:
                errors.append(("left_network",self.network))
        if errors:raise RuntimeError("R29_CLEANUP_NOT_COMPLETE:"+str(errors))

COMPOSE_OLD="""services:
  db:
    image: postgres:16
    volumes: [r29data:/var/lib/postgresql/data]
    healthcheck: {test: [CMD, pg_isready]}
  broker:
    image: redis:7-alpine
  api:
    image: localhost/tredven-r29-public-fastapi-worker-redis:417de5b
    depends_on: [db, broker]
    environment:
      DATABASE_URL: postgresql+asyncpg://postgres@db:5432/appdb
      CELERY_BROKER_URL: redis://broker:6379/0
  worker:
    image: localhost/tredven-r29-public-fastapi-worker-redis:417de5b
    depends_on: [db, broker]
    environment:
      DATABASE_URL: postgresql+asyncpg://postgres@db:5432/appdb
      CELERY_BROKER_URL: redis://broker:6379/0
volumes:
  r29data:
"""
COMPOSE_NEW=COMPOSE_OLD.replace("image: postgres:16","image: postgres:17",1)
REQUIRED=[("api","health"),("api","integration"),
          ("db","health"),("db","integration"),("db","data-migration"),("db","rollback"),
          ("worker","health"),("worker","integration")]

def prepare_source(root):
    fixture=root/"source"
    fixture.mkdir(mode=0o700)
    cmd_git(fixture,"init","-q")
    cmd_git(fixture,"config","user.name","R29 synthetic system graph")
    cmd_git(fixture,"config","user.email","r29@example.invalid")
    (fixture/"compose.yaml").write_text(COMPOSE_OLD)
    cmd_git(fixture,"add","compose.yaml")
    cmd_git(fixture,"commit","-qm","baseline image postgres16")
    cmd_git(fixture,"tag","r29-base16")
    old=cmd_git(fixture,"rev-parse","HEAD")
    (fixture/"compose.yaml").write_text(COMPOSE_NEW)
    cmd_git(fixture,"add","compose.yaml")
    cmd_git(fixture,"commit","-qm","candidate image postgres17")
    cmd_git(fixture,"tag","r29-candidate17")
    new=cmd_git(fixture,"rev-parse","HEAD")
    return fixture,old,new

def pg_dump(db,out_path,net):
    args=("run","--rm","--pull=never","--network",net,
          "--security-opt=no-new-privileges","--entrypoint=pg_dump",
          DB17,"-h","db","-U","postgres","-d","appdb","-Fc",
          "--no-owner","--no-acl")
    with os.fdopen(os.open(out_path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as f:
        proc=subprocess.run(["podman",*args],stdout=f,stderr=subprocess.PIPE,timeout=90)
    if proc.returncode:
        raise RuntimeError("PGDUMP_SOURCE_FAILED "+proc.stderr.decode(errors="replace")[-500:])
    data=out_path.read_bytes()
    if not data.startswith(b"PGDMP") or len(data)<100:
        raise RuntimeError("UNEXPECTED_LOGICAL_DUMP_FILE")
    return {"sha256":sha(data),"bytes":len(data),"format":"pg_dump -Fc"}

def rust_gate(root,fixture,new,test_results):
    assert set(test_results)==set(REQUIRED),("UNMAPPED_TESTS",test_results.keys())
    request={
      "schema":"tredven.upstream.system-upgrade.v1",
      "project":"r29-real-fastapi-celery-redis-postgres",
      "repo":str(fixture),
      "baseline_tag":"r29-base16","candidate_tag":"r29-candidate17",
      "compose_path":"compose.yaml","upgrading_service":"db",
      "checks":[]
    }
    manifest=[]
    for svc,kind in REQUIRED:
        passed=test_results[(svc,kind)]
        item={
           "schema":"tredven.upstream.system-test-receipt.v1",
           "candidate_commit":new,
           "compose_sha256":sha(COMPOSE_NEW.encode()),
           "service":svc,"kind":kind,
           "result":"passed" if passed else "failed",
           "tests_passed":int(passed),"tests_failed":int(not passed),
           "isolated":True
        }
        blob=(json.dumps(item,indent=2,sort_keys=True)+"\n").encode()
        filename=f"receipt-{svc}-{kind}.json"
        path=root/filename
        with os.fdopen(os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as out:
            out.write(blob)
        request["checks"].append({
             "service":svc,"kind":kind,"artifact":str(path),"sha256":sha(blob)
        })
        manifest.append({"name":filename,"sha256":sha(blob),
                         "service":svc,"kind":kind,"passed":passed})
    request_file=root/"r29-review-config.json"
    request_file.write_text(json.dumps(request,sort_keys=True,indent=2)+"\n")
    rust=os.environ.get("TREDVEN_R29_RUST_CLI","")
    if not rust or not pathlib.Path(rust).is_file():
        raise RuntimeError("RUST_CLI_PATH_NOT_VERIFIED")
    command=[rust,"qualify-system","--config",str(request_file)]
    rv=run(*command,check=False,timeout=40)
    if rv.returncode!=2:
        raise RuntimeError("ROLLBACK_DATA_LOSS_WAS_NOT_BLOCKED_BY_RUST_GATE:"+
                           rv.stderr.decode(errors="replace")[-450:])
    decision=json.loads(rv.stdout)
    if decision["decision"]!="BLOCKED":
        raise RuntimeError("INVALID_RUST_POLICY_FOR_REAL_ROLLBACK_TEST")
    if decision["affected_services"]!=["api","db","worker"]:
        raise RuntimeError("INCORRECT_RELATION_GRAPH")
    if decision["total_required_checks"]!=8 or decision["covered_required_checks"]!=7:
        raise RuntimeError("RUST_COVERAGE_STATUS_MISMATCH")
    if not any(c["service"]=="db" and c["kind"]=="rollback" and c["status"]=="BLOCKED"
               for c in decision["required_checks"]):
        raise RuntimeError("ROLLBACK_NOT_HONORED")
    if decision["one_click_live_upgrade_authorized"] or decision["production_compatibility_proven"]:
        raise RuntimeError("FALSE_PRODUCTION_APPROVAL")
    (root/"r29-real-app-rust-gate.json").write_bytes(
        (json.dumps(decision,indent=2,sort_keys=True)+"\n").encode())
    # Attempt to create an upgrade candidate must fail without directory write.
    stage=root/"MUST_NOT_STAGE"
    blocked=run(*command,"--stage-dir",str(stage),check=False,timeout=30)
    if blocked.returncode!=1 or stage.exists():
        raise RuntimeError("RUST_UNSAFE_LOCAL_STAGE_BYPASS")
    return manifest,decision

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--output-name",required=True)
    args=parser.parse_args()
    if not re.fullmatch(r"r29-[a-z0-9-]{5,100}",args.output_name):
        raise RuntimeError("INVALID_TEST_OUTPUT_NAME")
    ids=check_preconditions()
    resultdir=REPO/"output"/args.output_name
    if resultdir.exists() or resultdir.is_symlink():
        raise RuntimeError("PRIVATE_TEST_RESULT_ALREADY_EXISTS")
    resultdir.mkdir(mode=0o700)
    fixture,old,new=prepare_source(resultdir)
    resource=Sandbox(resultdir)
    times={}
    app_observed={}
    start=time.monotonic()
    print("PINNED_PUBLIC_UPSTREAM_APP",PIN,flush=True)
    print("ROOTLESS_INTERNAL_NO_PORTS_BEGIN",flush=True)
    try:
        resource.setup()
        resource.db(DB16,old=True)
        resource.app(old=True)
        print("BASELINE_APP_API_WORKER_BROKER_DB16_UP",flush=True)
        app_observed["baseline"]=resource.verify_apps("baseline")
        old_count=app_observed["baseline"]["row_count"]
        old_contents=resource.sql(resource.db_old,
             "SELECT string_agg(content,',' ORDER BY content) FROM messages;")
        resource.shutdown_app(old=True)
        backupfile=resultdir/"synthetic-app-postgres16.backup"
        backup=pg_dump(resource.db_old,backupfile,resource.network)
        resource.drop(resource.db_old)
        print("SOURCE_BOUND_BACKUP_COMPLETE",backup["sha256"][:12],flush=True)
        resource.db(DB17,old=False)
        restored=p("exec","-i",resource.db_new,"pg_restore",
                   "--exit-on-error","--no-owner","--no-acl",
                   "-U","postgres","-d","appdb",
                   input=backupfile.read_bytes(),timeout=90)
        # Source app config/database schema is restored with Postgres's real tools.
        resource.app(old=False)
        print("CANDIDATE_APP_API_WORKER_BROKER_DB17_UP",flush=True)
        original=resource.http("GET","/messages/")
        assert len(original)==old_count
        app_observed["candidate"]=resource.verify_apps("candidate")
        new_count=app_observed["candidate"]["row_count"]
        assert new_count>old_count
        new_contents=resource.sql(resource.db_new,
            "SELECT string_agg(content,',' ORDER BY content) FROM messages;")
        assert "r29-candidate" in new_contents
        print("REAL_API_WORKER_WRITES_AFTER_UPGRADE_PASS",flush=True)
        resource.shutdown_app(old=False)
        resource.drop(resource.db_new)
        resource.db(DB16,old=True)
        resource.app(old=True)
        recovered=resource.http("GET","/messages/")
        recovered_contents=resource.sql(resource.db_old,
            "SELECT string_agg(content,',' ORDER BY content) FROM messages;")
        rollback_count=len(recovered)
        assert recovered_contents==old_contents
        assert rollback_count==old_count and rollback_count<new_count
        assert "r29-candidate" not in recovered_contents
        resource.shutdown_app(old=True)
        print("ROLLBACK_OLD_DATA_RESTORED_BUT_POST_CUTOVER_WRITES_LOST",flush=True)
        flags={item:True for item in REQUIRED}
        flags[("db","rollback")]=False
        manifest,policy=rust_gate(resultdir,fixture,new,flags)
        print("RUST_BLOCKS_AUTOMATIC_UPGRADE_BECAUSE_ROLLBACK_LOSES_WRITES",flush=True)
        result={
           "schema":"tredven.upstream.r29.real-upstream-app-e2e.v1",
           "result":"REAL_APPLICATION_MIGRATION_COMPATIBLE_ROLLBACK_WITH_NEW_WRITES_BLOCKED",
           "app_upstream":"https://github.com/paulohsz/FastAPI-Celery-Docker",
           "app_source_commit":PIN,"image_ids":ids,
           "source_fixture_baseline_commit":old,
           "source_fixture_candidate_commit":new,
           "candidate_compose_sha256":sha(COMPOSE_NEW.encode()),
           "rootless":True,"network":"isolated_internal","host_ports_published":0,
           "real_app_code_executed":True,
           "real_workflow":"FastAPI HTTP -> Redis -> Celery worker -> PostgreSQL",
           "database_migration":backup,
           "baseline_message_count":old_count,
           "after_upgrade_message_count":new_count,
           "after_rollback_message_count":rollback_count,
           "post_cutover_new_writes_lost_on_rollback":True,
           "observed_apps":app_observed,
           "test_receipts":manifest,
           "rust_gate_decision":policy["decision"],
           "rust_gate_covered_required":policy["covered_required_checks"],
           "rust_gate_total_required":policy["total_required_checks"],
           "ci_signature_provenance":"UNSIGNED_LOCAL_NOT_GITHUB_HOSTED",
           "one_click_upgrade_authorized":False,
           "production_ready":False,
           "no_user_data_or_production_access":True
        }
    finally:
        resource.cleanup()
        print("R29_ALL_DISPOSABLE_CONTAINERS_NETWORK_VOLUMES_REMOVED",flush=True)
    result["run_seconds"]=round(time.monotonic()-start,3)
    final=resultdir/"r29-local-real-app-evidence.json"
    with os.fdopen(os.open(final,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600),"wb") as f:
        f.write((json.dumps(result,indent=2,sort_keys=True)+"\n").encode())
    print(json.dumps({"result":result["result"],"observed":app_observed,
            "rust":policy["decision"],"seconds":result["run_seconds"],
            "receipt":str(final)},sort_keys=True),flush=True)

if __name__=="__main__":
    try:main()
    except (RuntimeError,AssertionError,ValueError,subprocess.TimeoutExpired) as error:
        print("R29_REAL_APP_E2E_FAILED:"+str(error),file=sys.stderr)
        raise SystemExit(1)
