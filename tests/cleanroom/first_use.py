#!/usr/bin/env python3
"""Public fd cleanroom E2E; neither independent-human nor signed-public-release proof."""
import hashlib,json,os,re,subprocess,tarfile,time
from pathlib import Path
ROOT=Path("/tmp/r22-user")
OUT=ROOT/"evidence"
ARCHIVE=ROOT/"candidate.tar.gz"
CLI=ROOT/"bin/tredven-upstream"
SOURCE=ROOT/"fd-source"
GIT_URL="https://github.com/sharkdp/fd.git"
OSV_SHA="fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8"
# The operator must separately establish this exact local artifact digest.
# It is NOT a substitute for Sigstore provenance in an external release.
RC_SHA=os.environ.get("R22_CANDIDATE_SHA256", "")
assert re.fullmatch(r"[a-f0-9]{64}",RC_SHA), "explicit 64-hex local test archive SHA required"
assert os.environ.get("R22_EXPLICIT_PUBLIC_OSV_REHEARSAL")=="yes", "public Git and OSV network opt-in required"
TAGS=("v10.4.2","v10.5.2")
durations={}
OUT.mkdir(mode=0o700)
(ROOT/".cache").mkdir(mode=0o700)
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def run(label,args,ok=(0,),capture=None):
 t=time.monotonic()
 p=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,timeout=200)
 durations[label]=round(time.monotonic()-t,3)
 if capture:
  (OUT/(capture+".json")).write_text(p.stdout)
  (OUT/(capture+".stderr")).write_text(p.stderr)
 if p.returncode not in ok:raise RuntimeError(f"{label} exited {p.returncode}: {p.stderr[:450]}")
 return p
assert digest(ARCHIVE)==RC_SHA
with tarfile.open(ARCHIVE,"r:gz") as tar:
 members=tar.getmembers()
 assert {m.name for m in members}=={"bin/tredven-upstream","LICENSE","README.md","THIRD_PARTY_NOTICES.txt","RUST_RUNTIME_NOTICES.html"}
 assert len(members)==5
 assert all(m.isfile() and 0<m.size<12000000 and not m.name.startswith("/") and ".." not in m.name for m in members)
 tar.extractall(ROOT)  # Five known safe regular files, exact SHA-pinned archive.
start=time.monotonic()
run("git_clone",["git","clone","--no-checkout","--quiet",GIT_URL,str(SOURCE)])
commits={tag:run("git_"+tag,["git","-C",str(SOURCE),"rev-parse",tag+"^{commit}"]).stdout.strip() for tag in TAGS}
assert commits == {
  "v10.4.2":"7027d45303b412be6fa9c09d689cc6276748fb38",
  "v10.5.2":"b2a287b3993768e0ec52f0852916917f23fb2a38"
}, "the public source Git objects no longer match the audited fixture"
first_cmd=[str(CLI),"review-local","--repo",str(SOURCE),"--project","r22-public-fd",
 "--from",TAGS[0],"--to",TAGS[1],"--install-pinned-osv","--allow-public-osv-network","--format","json"]
p=run("tredven_cold",first_cmd,(0,2,3),"tredven_cold")
review=json.loads(p.stdout)
assert review["decision"]=="REVIEW"
assert not review["production_ready"] and not review["release_authorized"]
osv=ROOT/".cache/tredven-upstream/tools/osv-scanner-v2.7.1-linux-amd64"
assert osv.stat().st_size==58187936 and digest(osv)==OSV_SHA
native_findings={}
native_packages={}
for tag,label in zip(TAGS,("baseline","candidate")):
 d=ROOT/label
 d.mkdir()
 lock=d/"Cargo.lock"
 lock.write_bytes(subprocess.run(["git","-C",str(SOURCE),"show",tag+":Cargo.lock"],check=True,stdout=subprocess.PIPE,timeout=20).stdout)
 p=run("native_"+label,[str(osv),"scan","source","--lockfile",str(lock),
       "--all-packages","--no-resolve","--format","json"],(0,1),"osv_"+label)
 x=json.loads(p.stdout)
 assert len(x["results"])==1 and x["results"][0]["source"]["path"]==str(lock)
 native_findings[label]=sorted(f"{pkg['package']['name']}:{v['id']}" for r in x["results"] for pkg in r["packages"] for v in pkg.get("vulnerabilities",[]))
 native_packages[label]=sum(len(r["packages"]) for r in x["results"])
 assert len(native_findings[label])==review[label]["scanner"]["vulnerability_occurrences"]
 assert review[label]["scanner"]["expected_subject_matched"]
warm=json.loads(run("tredven_warm",first_cmd,(0,2,3),"tredven_warm").stdout)
# OSV raw JSON includes a random private scan path; hash values are exact
# byte-evidence identifiers and are intentionally different on repeat runs.
# Compare every other field, preserving release/decision/coverage invariants.
unstable={"subject", "baseline_report_sha256", "candidate_report_sha256"}
meaning=lambda d:{k:v for k,v in d.items() if k not in unstable}
assert warm["decision"]==review["decision"]
assert meaning(warm["delta"])==meaning(review["delta"])
for side in ("baseline", "candidate"):
 assert warm[side]["scanner"]==review[side]["scanner"]
 assert warm[side]["input_lockfile_sha256"]==review[side]["input_lockfile_sha256"]
assert warm["source"]==review["source"]
receipt={
 "schema":"tredven.upstream.r22.cleanroom.v1",
 "evidence_level":"LOCAL_CLEAN_DEBIAN_12_REAL_PUBLIC_DATA_NOT_EXTERNAL_HUMAN",
 "signed_public_release":False,"external_human_tested":False,
 "reference_repo":GIT_URL,"tags":TAGS,"tag_commits":commits,
 "candidate_archive_sha256":RC_SHA,"candidate_binary_sha256":digest(CLI),
 "osv_scanner_sha256":OSV_SHA,"native_osv_advisories":native_findings,
 "native_osv_packages":native_packages,
 "tredven_decision":review["decision"],
 "tredven_resolved_occurrences":review["delta"]["resolved_occurrences"],
 "tredven_new_occurrences":review["delta"]["new_occurrences"],
 "wall_seconds":durations,
 "total_seconds_including_clone":round(time.monotonic()-start,3),
 "notes":["one clean container and one public Rust example","unpublished unsigned Tredven test archive",
 "native OSV comparator is CLI and not official OSV PR Action","no usability or business value claim",
 "OSV database can change; source and scanner bytes pinned; no external human"]
}
(OUT/"receipt.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
summary=("# R22 first-use independent-environment rehearsal\n\n"+
 f"fd {TAGS[0]} -> {TAGS[1]}. Native OSV findings: {len(native_findings['baseline'])} -> {len(native_findings['candidate'])}.\n\n"+
 f"Tredven verdict {review['decision']}; resolved {receipt['tredven_resolved_occurrences']}, new {receipt['tredven_new_occurrences']}.\n\n"+
 f"Git clone {durations['git_clone']}s, Tredven fresh-cache {durations['tredven_cold']}s, "+
 f"Tredven warm {durations['tredven_warm']}s, direct native scans "+
 f"{durations['native_baseline']}s + {durations['native_candidate']}s.\n\n"+
 "This is one automated clean Debian 12 trial using real public data, not an independent human, not a signed release, and not proof of superior usability.\n")
(OUT/"summary.md").write_text(summary)
print("R22_CLEANROOM_REAL_PUBLIC_DATA_E2E_PASS")
print(summary)
