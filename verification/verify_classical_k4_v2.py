#!/usr/bin/env python3
"""Verify provenance, calibration chronology, and exact K4 survivors."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'verification'))
from verify_classical_schedules_v4 import solve,reencrypt,templates
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def verify(run):
 manifest=load(run/'manifest.json');spec_path=ROOT/'experiments'/f"{manifest['experiment_id']}.json";spec=load(spec_path)
 if manifest['spec_sha256']!=sha(spec_path):raise ValueError('spec hash mismatch')
 for name,digest in spec['evidence_file_hashes'].items():
  if sha(ROOT/name)!=digest:raise ValueError('frozen input mismatch: '+name)
 if manifest['evidence_file_hashes']!=spec['evidence_file_hashes']:raise ValueError('manifest evidence binding mismatch')
 if sha(ROOT/spec['request_path'])!=spec['request_sha256'] or manifest['request_sha256']!=spec['request_sha256']:raise ValueError('request binding mismatch')
 for field in ('calibration_completion','calibration_verification'):
  path=ROOT/spec[field];expected=spec[field+'_sha256']
  if sha(path)!=expected or manifest[field+'_sha256']!=expected:raise ValueError(field+' hash mismatch')
 cc=load(ROOT/spec['calibration_completion']);cv=load(ROOT/spec['calibration_verification'])
 if cc.get('status')!='completed' or not cc.get('calibration_passed') or cv.get('status')!='passed':raise ValueError('calibration status failed')
 for key,value in spec['required_calibration_gates'].items():
  if cv.get(key)!=value:raise ValueError('calibration gate mismatch: '+key)
 if sha(run/'attacker-binary')!=spec['expected_binary_sha256'] or manifest['binary_sha256']!=spec['expected_binary_sha256']:raise ValueError('binary mismatch')
 request=load(ROOT/spec['request_path']);actual=load(run/'result.json');case=request['cases'][0];expected=[x for t in templates() if (x:=solve(case,t)) is not None];expected.sort(key=lambda x:x['template_id'])
 if actual['cases'][0]['survivors']!=expected:raise ValueError('exact survivor/order mismatch')
 if any(not reencrypt(x,case['ciphertext']) for x in expected):raise ValueError('witness reencryption failed')
 if actual['operations']!=spec['operation_cap'] or manifest['operation_cap']!=spec['operation_cap']:raise ValueError('operation count/cap mismatch')
 counts={f:sum(x['family']==f for x in expected) for f in ('repeating_interrupted','progressive','autokey')}
 return {'schema_version':1,'status':'verified','operation_unit':'canonical_template_check','operations':actual['operations'],'operation_cap':spec['operation_cap'],'survivors':len(expected),'survivors_by_family':counts,'witnesses_reencrypted':len(expected),'unknowns':0,'calibration_gate_verified':True}
if __name__=='__main__':
 try:print(json.dumps(verify(Path(sys.argv[1]).resolve()),indent=2,sort_keys=True))
 except Exception as e:print('K4 verification failed: '+str(e),file=sys.stderr);raise SystemExit(1)
