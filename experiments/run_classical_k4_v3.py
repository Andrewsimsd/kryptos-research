#!/usr/bin/env python3
"""Run K4 only after the corrected Milestone 11 calibration gate passes."""
import hashlib, json, shutil, subprocess, sys, time
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'experiments/CLASSICAL-SCHEDULES-K4-0003.json'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def dump(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def now():return datetime.now(timezone.utc).isoformat()
def event(x):
 with (ROOT/'experiments/registry.jsonl').open('a') as f:f.write(json.dumps(x,sort_keys=True)+'\n')

def main():
 if len(sys.argv)!=2:raise SystemExit('usage: run_classical_k4_v2.py RUN_DIR')
 spec=load(SPEC);run=(ROOT/sys.argv[1]).resolve()
 if run.exists() or not run.is_relative_to(ROOT/'results'):raise SystemExit('run directory must be new and below results/')
 if sha(ROOT/spec['request_path'])!=spec['request_sha256']:raise SystemExit('request hash mismatch')
 for name,digest in spec['evidence_file_hashes'].items():
  if sha(ROOT/name)!=digest:raise SystemExit('frozen hash mismatch: '+name)
 cal_completion=ROOT/spec['calibration_completion'];cal_verification=ROOT/spec['calibration_verification']
 if sha(cal_completion)!=spec['calibration_completion_sha256'] or sha(cal_verification)!=spec['calibration_verification_sha256']:raise SystemExit('calibration artifact hash mismatch')
 cc,cv=load(cal_completion),load(cal_verification)
 if cc.get('status')!='completed' or not cc.get('calibration_passed') or cv.get('status')!='passed':raise SystemExit('calibration did not pass')
 for key,value in spec['required_calibration_gates'].items():
  if cv.get(key)!=value:raise SystemExit('calibration gate mismatch: '+key)
 subprocess.run(['cargo','build','--release','--locked'],cwd=ROOT,check=True)
 binary=ROOT/'target/release/kryptos-research';binary_hash=sha(binary)
 if binary_hash!=spec['expected_binary_sha256']:raise SystemExit('compiled binary hash mismatch')
 run.mkdir(parents=True);run_id=str(run.relative_to(ROOT));event({'experiment_id':spec['experiment_id'],'run_id':run_id,'status':'started','at':now()});start=time.monotonic()
 manifest={'schema_version':1,'experiment_id':spec['experiment_id'],'run_id':run_id,'spec_sha256':sha(SPEC),'evidence_file_hashes':spec['evidence_file_hashes'],'request_path':spec['request_path'],'request_sha256':spec['request_sha256'],'calibration_completion':spec['calibration_completion'],'calibration_completion_sha256':spec['calibration_completion_sha256'],'calibration_verification':spec['calibration_verification'],'calibration_verification_sha256':spec['calibration_verification_sha256'],'operation_unit':'canonical_template_check','operation_cap':spec['operation_cap'],'binary_sha256':binary_hash,'wall_time_cap_seconds':spec['wall_time_cap_seconds']};dump(run/'manifest.json',manifest);shutil.copy2(binary,run/'attacker-binary')
 with (run/'result.json').open('wb') as out,(run/'attacker.stderr').open('wb') as err:subprocess.run([binary,'classical-schedules',ROOT/spec['request_path']],cwd=ROOT,stdout=out,stderr=err,check=True,timeout=spec['wall_time_cap_seconds'])
 if sha(binary)!=binary_hash:raise SystemExit('binary changed during K4 attack')
 result=load(run/'result.json')
 if result['operations']!=spec['operation_cap'] or result['canonical_templates']!=spec['operation_cap']:raise SystemExit('K4 operation accounting mismatch')
 verify=subprocess.run([sys.executable,ROOT/'verification/verify_classical_k4_v3.py',run],cwd=ROOT,capture_output=True,text=True);(run/'verification.stderr').write_text(verify.stderr)
 if verify.returncode:raise SystemExit('K4 verification failed: '+verify.stderr)
 (run/'verification.json').write_text(verify.stdout);art={p.name:sha(p) for p in sorted(run.iterdir()) if p.name!='completion.json'};elapsed=time.monotonic()-start
 if elapsed>spec['wall_time_cap_seconds']:raise SystemExit('wall cap exceeded after final artifact hashing')
 completion={'schema_version':1,'experiment_id':spec['experiment_id'],'run_id':run_id,'status':'completed','calibration_gate_passed':True,'operation_unit':'canonical_template_check','operations':result['operations'],'operation_cap':spec['operation_cap'],'binary_sha256':binary_hash,'wall_seconds':elapsed,'unknowns':0,'artifact_sha256':art};dump(run/'completion.json',completion);event({'experiment_id':spec['experiment_id'],'run_id':run_id,'status':'completed','at':now(),'completion_sha256':sha(run/'completion.json')});print(json.dumps(completion,indent=2));return 0
if __name__=='__main__':raise SystemExit(main())
