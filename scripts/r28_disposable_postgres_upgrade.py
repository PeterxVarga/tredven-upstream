#!/usr/bin/env python3
"""R28 isolated Postgres 16 -> 17 logical migration, client probes, rollback and Rust gate.

Only disposable rootless Podman resources with a unique r28 prefix are touched.
NO existing containers/volumes, host ports, public network, production data, or deployment.
All produced receipts remain local and UNATTESTED; R27 may return REVIEW, never production approval.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_ROOT = PROJECT_ROOT / "output"
IMAGE16 = "docker.io/library/postgres:16"
IMAGE17 = "docker.io/library/postgres:17"
PREFIX = "tredven-r28-isolated-"
SQL_SETUP = """
CREATE SCHEMA app;
CREATE TABLE app.orders (
  id integer PRIMARY KEY, sku text NOT NULL, units integer NOT NULL CHECK (units > 0)
);
CREATE TABLE app.jobs (
  id integer PRIMARY KEY, order_id integer NOT NULL REFERENCES app.orders(id),
  status text NOT NULL CHECK (status IN ('pending','done'))
);
INSERT INTO app.orders VALUES (1,'unit-alpha',2),(2,'unit-beta',5);
INSERT INTO app.jobs VALUES (101,1,'pending'),(102,2,'pending');
CREATE VIEW app.order_totals AS SELECT count(*)::int AS orders, sum(units)::int AS units FROM app.orders;
"""
COMPOSE16 = """services:
  db:
    image: postgres:16
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck: {test: [CMD, pg_isready]}
  api:
    image: postgres:17
    depends_on: [db]
  worker:
    image: postgres:17
    depends_on: [api]
volumes:
  pgdata:
"""
COMPOSE17 = COMPOSE16.replace("image: postgres:16", "image: postgres:17", 1)
EXPECTED_FINGERPRINT_SQL = (
    "SELECT md5(COALESCE((SELECT string_agg("
    "id::text || ':' || sku || ':' || units::text,',' ORDER BY id) FROM app.orders),'')"
    " || '#' || COALESCE((SELECT string_agg("
    "id::text || ':' || order_id::text || ':' || status,',' ORDER BY id)"
    " FROM app.jobs),''));"
)
CHECKS = [
    ("db","health"),("db","integration"),("db","data-migration"),("db","rollback"),
    ("api","health"),("api","integration"),("worker","health"),("worker","integration")
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(args: list[str], *, timeout: int = 50, input_data: bytes | None = None,
        check: bool = True) -> subprocess.CompletedProcess[bytes]:
    p = subprocess.run(args, input=input_data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError(
            f"{args[0]} {args[1:4]} failed rc={p.returncode}: "
            + p.stderr.decode("utf-8","replace")[-550:]
        )
    return p


def podman(*args: str, timeout: int = 50, check: bool = True,
           input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    return run(["podman", *args], timeout=timeout, check=check, input_data=input_data)


def stdout(p: subprocess.CompletedProcess[bytes]) -> str:
    return p.stdout.decode("utf-8", "strict").strip()


def wait_ready(db: str, seconds: int = 35) -> None:
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        # Official postgres entrypoint launches a temporary Unix-socket-only
        # server and stops it before accepting real TCP clients. A socket-only
        # pg_isready can incorrectly mark initialisation complete too early.
        p = podman("exec", "--user", "postgres", db, "pg_isready",
                   "-h", "127.0.0.1", "-U", "postgres", "-d", "r28demo",
                   check=False, timeout=10)
        if p.returncode == 0:
            return
        time.sleep(0.35)
    raise RuntimeError("DISPOSABLE_DATABASE_DID_NOT_BECOME_READY")


class Isolated:
    def __init__(self, output: Path):
        self.output = output
        self.suffix = uuid.uuid4().hex[:12]
        self.vol16 = PREFIX + "data16-" + self.suffix
        self.vol17 = PREFIX + "data17-" + self.suffix
        self.db16 = PREFIX + "pg16-" + self.suffix
        self.db17 = PREFIX + "pg17-" + self.suffix
        self.volumes: list[str] = []
        self.containers: list[str] = []

    def new_volume(self, name: str) -> None:
        assert name.startswith(PREFIX)
        podman("volume", "create", "--label", "tredven-r28=disposable",
               "--label", "tredven-r28-owner=local-only", name)
        self.volumes.append(name)

    def start(self, name: str, image: str, volume: str) -> None:
        assert name.startswith(PREFIX) and volume in self.volumes
        podman("run", "-d", "--pull=never", "--network=none",
               "--security-opt=no-new-privileges", "--pids-limit=192",
               "--name", name, "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
               "-e", "POSTGRES_DB=r28demo",
               "-v", volume + ":/var/lib/postgresql/data", image)
        self.containers.append(name)
        wait_ready(name)

    def client(self, db: str, role: str, sql: str, *,
               expect: str | None = None) -> str:
        assert db in self.containers and role in ("api","worker","db")
        # This is a separate, ephemeral PostgreSQL client *container* joined
        # only to the tested database container's network namespace.
        args = ("run", "--rm", "--pull=never",
                "--network=container:" + db,
                "--security-opt=no-new-privileges", "--pids-limit=64",
                "--entrypoint=psql", IMAGE17,
                "-h", "127.0.0.1", "-U", "postgres", "-d", "r28demo",
                "-v", "ON_ERROR_STOP=1", "-At", "-c", sql)
        value = stdout(podman(*args, timeout=45))
        if expect is not None and value != expect:
            raise AssertionError(f"{role} SQL result mismatch: {value!r} != {expect!r}")
        return value

    def health(self, db: str) -> None:
        p = podman("run", "--rm", "--pull=never",
                   "--network=container:" + db,
                   "--security-opt=no-new-privileges", "--entrypoint=pg_isready",
                   IMAGE17, "-h", "127.0.0.1", "-U", "postgres",
                   "-d", "r28demo", timeout=30)
        assert "accepting connections" in stdout(p)

    def stop(self, name: str) -> None:
        assert name in self.containers
        podman("stop", "--time", "6", name, timeout=35)
        podman("rm", name, timeout=20)
        self.containers.remove(name)

    def cleanup(self) -> None:
        failures=[]
        for name in reversed(self.containers):
            result=podman("rm", "-f", name, check=False, timeout=30)
            if result.returncode:failures.append(("container",name,result.returncode))
        for vol in reversed(self.volumes):
            result=podman("volume", "rm", "-f", vol, check=False, timeout=30)
            if result.returncode:failures.append(("volume",vol,result.returncode))
        for name in self.containers:
            if podman("container","exists",name,check=False).returncode == 0:
                failures.append(("container-still-present",name))
        for vol in self.volumes:
            if podman("volume","exists",vol,check=False).returncode == 0:
                failures.append(("volume-still-present",vol))
        if failures:
            raise RuntimeError("ISOLATED_RESOURCE_CLEANUP_FAILED:" + repr(failures))


def git(source: Path, *args: str) -> str:
    env=os.environ.copy()
    env.update({"GIT_CONFIG_NOSYSTEM":"1",
                "GIT_CONFIG_GLOBAL":"/dev/null",
                "GIT_TERMINAL_PROMPT":"0"})
    p=subprocess.run(["git","-C",str(source),*args],env=env,
                     capture_output=True,text=True,timeout=20,check=True)
    return p.stdout.strip()


def source_fixture(out: Path) -> tuple[Path,str,str]:
    src=out/"git-fixture"
    src.mkdir(mode=0o700)
    git(src,"init","-q")
    git(src,"config","user.name","R28 isolated synthetic validation")
    git(src,"config","user.email","r28@example.invalid")
    (src/"compose.yaml").write_text(COMPOSE16)
    git(src,"add","compose.yaml")
    git(src,"commit","-qm","synthetic baseline postgres16")
    git(src,"tag","r28-16")
    old=git(src,"rev-parse","HEAD")
    (src/"compose.yaml").write_text(COMPOSE17)
    git(src,"add","compose.yaml")
    git(src,"commit","-qm","synthetic candidate postgres17")
    git(src,"tag","r28-17")
    new=git(src,"rev-parse","HEAD")
    if git(src,"status","--porcelain"):
        raise RuntimeError("SYNTHETIC_GIT_FIXTURE_UNCLEAN")
    return src,old,new


def preflight() -> dict:
    if os.geteuid()==0:
        raise RuntimeError("DO_NOT_RUN_AS_ROOT")
    p=podman("info","--format","{{.Host.Security.Rootless}}")
    if stdout(p)!="true":
        raise RuntimeError("ROOTLESS_PODMAN_REQUIRED")
    images={}
    for image in (IMAGE16,IMAGE17):
        p=podman("image","exists",image,check=False)
        if p.returncode:
            raise RuntimeError("REQUIRED_CACHED_IMAGE_UNAVAILABLE:" + image)
        images[image]=stdout(podman("image","inspect",image,"--format","{{.Id}}"))
    if OUTPUT_ROOT.is_symlink() or not OUTPUT_ROOT.is_dir():
        raise RuntimeError("OUTPUT_ROOT_NOT_LOCAL_DIRECTORY")
    return images


def dump_with_postgres17(db: str, path: Path) -> dict:
    # New-version client logically reads old-version server over isolated
    # network namespace; backup bytes written to an owner-private local file.
    args=["podman","run","--rm","--pull=never",
          "--network=container:"+db,
          "--security-opt=no-new-privileges","--entrypoint=pg_dump",
          IMAGE17,"-h","127.0.0.1","-U","postgres",
          "-d","r28demo","-Fc","--no-owner","--no-acl"]
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,"wb") as out:
        p=subprocess.run(args,stdout=out,stderr=subprocess.PIPE,timeout=90)
    if p.returncode:
        raise RuntimeError("ISOLATED_PGDUMP_FAILED:"+
                           p.stderr.decode("utf-8","replace")[-450:])
    data=path.read_bytes()
    if not data.startswith(b"PGDMP") or len(data)<100:
        raise RuntimeError("UNEXPECTED_PGDUMP_FORMAT")
    return {"sha256":sha(data),"bytes":len(data),"source_server":"PostgreSQL 16",
            "dump_client":"PostgreSQL 17","format":"pg_dump -Fc"}


def restore_to_postgres17(db: str,path: Path) -> None:
    data=path.read_bytes()
    p=podman("exec","-i",db,"pg_restore",
             "--exit-on-error","--no-owner","--no-acl",
             "-U","postgres","-d","r28demo",
             input_data=data,timeout=90)
    if p.returncode:
        raise RuntimeError("ISOLATED_RESTORE_FAILED")


def qualify(out: Path, source: Path, commit: str, checks: dict, dry_fail: bool=False) -> dict:
    config={"schema":"tredven.upstream.system-upgrade.v1",
            "project":"r28-pg16-pg17-disposable",
            "repo":str(source),"baseline_tag":"r28-16",
            "candidate_tag":"r28-17",
            "compose_path":"compose.yaml","upgrading_service":"db",
            "checks":[]}
    config_hash=sha(COMPOSE17.encode())
    assert set(checks)==set(CHECKS)
    for service,kind in CHECKS:
        observed=checks[(service,kind)]
        result="failed" if dry_fail and (service,kind)==("db","data-migration") else "passed"
        receipt={"schema":"tredven.upstream.system-test-receipt.v1",
                 "candidate_commit":commit,"compose_sha256":config_hash,
                 "service":service,"kind":kind,
                 "result":result,
                 "tests_passed":int(result=="passed" and observed),
                 "tests_failed":int(result=="failed"),
                 "isolated":True}
        path=out/f"test-{service}-{kind}{'-injected' if dry_fail else ''}.json"
        raw=(json.dumps(receipt,sort_keys=True,indent=2)+"\n").encode()
        fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,"wb") as f:f.write(raw)
        config["checks"].append({"service":service,"kind":kind,
                                 "artifact":str(path),"sha256":sha(raw)})
    request=out/("qualification-injected-failure.json" if dry_fail else "qualification-passed.json")
    request.write_text(json.dumps(config,indent=2)+"\n")
    stage=out/("MUST_NOT_STAGE" if dry_fail else "qualified-local-stage")
    rust=os.environ.get("TREDVEN_R28_RUST_CLI")
    if not rust:
        raise RuntimeError("EXPLICIT_RUST_CLI_PATH_REQUIRED")
    binary=Path(rust).resolve()
    if not binary.is_file() or not os.access(binary,os.X_OK):
        raise RuntimeError("RUST_BINARY_UNAVAILABLE")
    args=[str(binary),"qualify-system","--config",str(request),"--stage-dir",str(stage)]
    report=run(args,timeout=30,check=False)
    if dry_fail:
        if report.returncode != 1 or stage.exists():
            raise RuntimeError("INJECTED_TEST_FAILURE_DID_NOT_CLOSE_STAGE_GATE")
        # R27 deliberately suppresses report when attempted local stage is unsafe.
        raw=run(args[:-2],timeout=30,check=False)
        if raw.returncode!=2: raise RuntimeError("INJECTED_TEST_FAILURE_NOT_BLOCKED")
        result=json.loads(raw.stdout)
        if result["decision"]!="BLOCKED":raise RuntimeError("INVALID_FAIL_CLOSED_VERDICT")
    else:
        if report.returncode:
            raise RuntimeError("REAL_ISOLATED_PASS_DID_NOT_QUALIFY:"+report.stderr.decode()[-450:])
        result=json.loads(report.stdout)
        if result["decision"]!="REVIEW" or not stage.is_dir():
            raise RuntimeError("REAL_LOCAL_STAGE_NOT_CREATED")
        if (stage/"candidate.compose.yaml").read_bytes()!=COMPOSE17.encode():
            raise RuntimeError("STAGED_CANDIDATE_NOT_COMMIT_BOUND")
        if result["covered_required_checks"]!=8 or result["total_required_checks"]!=8:
            raise RuntimeError("INCOMPLETE_SCOPE_CLAIM")
        if result["production_compatibility_proven"] or result["one_click_live_upgrade_authorized"]:
            raise RuntimeError("FALSE_LIVE_AUTHORIZATION")
    dest=out/("gate-injected-blocked.json" if dry_fail else "gate-real-review.json")
    dest.write_bytes(json.dumps(result,indent=2,sort_keys=True).encode()+b"\n")
    return result


def main() -> None:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-name",required=True)
    args=parser.parse_args()
    if not re.fullmatch(r"r28-[a-z0-9-]{5,100}",args.output_name):
        raise RuntimeError("OUTPUT_NAME_NOT_WHITELISTED")
    image_digests=preflight()
    out=OUTPUT_ROOT/args.output_name
    if out.exists() or out.is_symlink():
        raise RuntimeError("EXISTING_OUTPUT_WILL_NOT_BE_OVERWRITTEN")
    out.mkdir(mode=0o700)
    source,baseline,candidate=source_fixture(out)
    resources=Isolated(out)
    steps=[]
    tests={}
    begin=time.perf_counter()
    # Persist only synthetic evidence. No passwords/secrets are ever read.
    try:
        resources.new_volume(resources.vol16)
        resources.new_volume(resources.vol17)
        resources.start(resources.db16,IMAGE16,resources.vol16)
        podman("exec","--user","postgres",resources.db16,
               "psql","-U","postgres","-d","r28demo",
               "-v","ON_ERROR_STOP=1","-c",SQL_SETUP)
        baseline_fingerprint=resources.client(resources.db16,"db",EXPECTED_FINGERPRINT_SQL)
        assert len(baseline_fingerprint)==32
        assert resources.client(resources.db16,"api",
            "SELECT orders::text || '|' || units::text FROM app.order_totals;")=="2|7"
        assert resources.client(resources.db16,"worker",
            "SELECT count(*) FROM app.jobs WHERE status='pending';")=="2"
        steps.append("POSTGRES16_APP_AND_WORKER_BASELINE_VERIFIED")
        print("BASELINE_PG16_TWO_CLIENT_CONTRACTS_VERIFIED",flush=True)
        dump_file=out/"isolated-postgres16.backup"
        dump_evidence=dump_with_postgres17(resources.db16,dump_file)
        steps.append("PG17_CLIENT_LOGICAL_PG16_DUMP_COMPLETED")
        resources.stop(resources.db16)
        resources.start(resources.db17,IMAGE17,resources.vol17)
        restore_to_postgres17(resources.db17,dump_file)
        steps.append("POSTGRES17_NEW_VOLUME_RESTORED_FROM_PG16_LOGICAL_BACKUP")
        print("PG16_TO_PG17_LOGICAL_RESTORE_SUCCEEDED",flush=True)

        resources.health(resources.db17)
        version=resources.client(resources.db17,"db","SHOW server_version_num;")
        assert int(version)>=170000 and int(version)<180000
        tests[("db","health")]=True
        tests[("api","health")]=resources.client(resources.db17,"api","SELECT 1;")=="1"
        tests[("worker","health")]=resources.client(resources.db17,"worker","SELECT 1;")=="1"
        after_fp=resources.client(resources.db17,"db",EXPECTED_FINGERPRINT_SQL)
        assert after_fp==baseline_fingerprint
        assert resources.client(resources.db17,"db",
            "SELECT count(*) FROM app.orders o JOIN app.jobs j ON j.order_id=o.id;")=="2"
        tests[("db","integration")]=True
        tests[("db","data-migration")]=True

        api=resources.client(resources.db17,"api",
           "BEGIN; INSERT INTO app.orders VALUES (99,'temp-write',4);"
           " SELECT count(*) FROM app.orders; ROLLBACK;")
        assert "3" in api.splitlines()
        assert resources.client(resources.db17,"api",
            "SELECT orders::text || '|' || units::text FROM app.order_totals;")=="2|7"
        tests[("api","integration")]=True
        worker=resources.client(resources.db17,"worker",
           "BEGIN; UPDATE app.jobs SET status='done' WHERE id=101 RETURNING id; ROLLBACK;")
        assert "101" in worker.splitlines()
        assert resources.client(resources.db17,"worker",
            "SELECT count(*) FROM app.jobs WHERE status='pending';")=="2"
        tests[("worker","integration")]=True
        assert resources.client(resources.db17,"db",EXPECTED_FINGERPRINT_SQL)==baseline_fingerprint
        steps.append("PG17_DATA_API_WORKER_READ_WRITE_ROLLBACKED_TRANSACTIONS_PASS")
        print("PG17_SEPARATE_API_WORKER_CLIENT_CONTRACTS_PASS",flush=True)

        # Explicit cutover test: stop new server, remount *only* untouched old
        # volume, then confirm old server/data still work. No live writes since dump.
        resources.stop(resources.db17)
        resources.start(resources.db16,IMAGE16,resources.vol16)
        resources.health(resources.db16)
        rollback_fingerprint=resources.client(resources.db16,"db",EXPECTED_FINGERPRINT_SQL)
        assert rollback_fingerprint==baseline_fingerprint
        assert resources.client(resources.db16,"api",
            "SELECT orders::text || '|' || units::text FROM app.order_totals;")=="2|7"
        assert resources.client(resources.db16,"worker",
            "SELECT count(*) FROM app.jobs WHERE status='pending';")=="2"
        tests[("db","rollback")]=True
        steps.append("ORIGINAL_PG16_DATA_VOLUME_RESTART_AND_CLIENT_CONTRACTS_PASS")
        print("PG16_ORIGINAL_VOLUME_ROLLBACK_VERIFIED",flush=True)

        assert len(tests)==8 and all(tests.values())
        review=qualify(out,source,candidate,tests)
        negative=qualify(out,source,candidate,tests,dry_fail=True)
        assert review["decision"]=="REVIEW" and negative["decision"]=="BLOCKED"
        steps.append("RUST_R27_REAL_EVIDENCE_LOCAL_STAGE_REVIEW_AND_INJECTED_FAIL_CLOSED")
        print("RUST_GATE_REAL_TESTS_REVIEW_AND_INJECTED_FAILURE_BLOCKED",flush=True)
        status="ISOLATED_REAL_PG16_PG17_MIGRATION_CLIENT_CONTRACTS_ROLLBACK_PASS"
    finally:
        resources.cleanup()
        print("ALL_DISPOSABLE_SERVER_CONTAINERS_AND_VOLUMES_CLEANED",flush=True)
    receipt={
       "schema":"tredven.upstream.r28.isolated-postgres-real-upgrade.v1",
       "result":status,"evidence_level":"SYNTHETIC_TEST_DATA_REAL_ROOTLESS_PODMAN_AND_POSTGRES_SQL",
       "baseline_commit":baseline,"candidate_commit":candidate,
       "candidate_compose_sha256":sha(COMPOSE17.encode()),
       "baseline_fingerprint":baseline_fingerprint,
       "after_migration_fingerprint":after_fp,"after_rollback_fingerprint":rollback_fingerprint,
       "migration":dump_evidence,"source_images":image_digests,
       "tests_observed":[{"service":x,"kind":y,"pass":bool(z)} for (x,y),z in sorted(tests.items())],
       "source_bound_rust_gate":"REVIEW_UNATTESTED_NO_PRODUCTION_APPROVAL",
       "negative_fault_injection":"BLOCKED_LOCAL_STAGE_DENIED",
       "runtime_seconds":round(time.perf_counter()-begin,3),
       "rootless":True,"network":"none_and_container_shared_namespace_only",
       "host_ports_published":0,"new_disposable_volumes_only":True,
       "real_application_code_executed":False,
       "client_type":"isolated_postgresql_psql_containers_simulating_api_worker_sql_contracts",
       "full_prod_compatibility":False,"one_click_upgrade_authorized":False,
       "no_live_writes_after_snapshot":True,"rollback_excludes_new_version_writes":True,
       "steps":steps
    }
    (out/"r28-e2e-receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"result":status,"duration_seconds":receipt["runtime_seconds"],
          "gate":review["decision"],"fault_injection":negative["decision"],
          "baseline_commit":baseline,"candidate_commit":candidate,
          "receipt":str(out/"r28-e2e-receipt.json")},sort_keys=True),flush=True)


if __name__=="__main__":
    try:main()
    except (ValueError,AssertionError,RuntimeError,subprocess.TimeoutExpired) as e:
        print("R28_ISOLATED_E2E_FAILED:"+str(e),file=sys.stderr)
        sys.exit(1)
