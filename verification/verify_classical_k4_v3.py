#!/usr/bin/env python3
"""Strictly verify provenance, calibration chronology, and K4 survivors."""
import hashlib,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'verification'))
from verify_classical_schedules_v5 import solve,reencrypt,templates
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(p):return json.loads(p.read_text())
def require_equal(actual,expected,label):
 if actual!=expected:raise ValueError(label+' mismatch')
def verify(run):
 run=run.resolve()
 if not run.is_relative_to(ROOT/'results'):raise ValueError('run path is outside results')
 manifest=load(run/'manifest.json')
 if not isinstance(manifest.get('experiment_id'),str):raise ValueError('manifest experiment_id is invalid')
 spec_path=ROOT/'experiments'/f"{manifest['experiment_id']}.json";spec=load(spec_path)
 expected_manifest={
  'schema_version':1,'experiment_id':spec['experiment_id'],'run_id':str(run.relative_to(ROOT)),
  'spec_sha256':sha(spec_path),'evidence_file_hashes':spec['evidence_file_hashes'],
  'request_path':spec['request_path'],'request_sha256':spec['request_sha256'],
  'calibration_completion':spec['calibration_completion'],
  'calibration_completion_sha256':spec['calibration_completion_sha256'],
  'calibration_verification':spec['calibration_verification'],
  'calibration_verification_sha256':spec['calibration_verification_sha256'],
  'operation_unit':spec['operation_unit'],'operation_cap':spec['operation_cap'],
  'binary_sha256':spec['expected_binary_sha256'],
  'wall_time_cap_seconds':spec['wall_time_cap_seconds'],
 }
 require_equal(manifest,expected_manifest,'complete manifest')
 for name,digest in spec['evidence_file_hashes'].items():
  if sha(ROOT/name)!=digest:raise ValueError('frozen input mismatch: '+name)
 if sha(ROOT/spec['request_path'])!=spec['request_sha256']:raise ValueError('request binding mismatch')
 for field in ('calibration_completion','calibration_verification'):
  path=ROOT/spec[field];expected=spec[field+'_sha256']
  if sha(path)!=expected:raise ValueError(field+' hash mismatch')
 cc=load(ROOT/spec['calibration_completion']);cv=load(ROOT/spec['calibration_verification'])
 if cc.get('status')!='completed' or not cc.get('calibration_passed') or cv.get('status')!='passed':raise ValueError('calibration status failed')
 for key,value in spec['required_calibration_gates'].items():
  if cv.get(key)!=value:raise ValueError('calibration gate mismatch: '+key)
 if sha(run/'attacker-binary')!=spec['expected_binary_sha256']:raise ValueError('binary mismatch')
 request=load(ROOT/spec['request_path'])
 if set(request)!={'schema_version','cases','operation_cap'} or request['schema_version']!=1 or request['operation_cap']!=spec['operation_cap'] or len(request['cases'])!=1:raise ValueError('request metadata mismatch')
 actual=load(run/'result.json');case=request['cases'][0]
 expected=[x for t in templates() if (x:=solve(case,t)) is not None];expected.sort(key=lambda x:x['template_id'])
 expected_metadata={'schema_version':1,'raw_parameter_tuples':65856,'canonical_coordinate_maps':200,'canonical_templates':2192,'template_counts':{'autokey':192,'progressive':1600,'repeating_interrupted':400},'operations':spec['operation_cap']}
 for key,value in expected_metadata.items():require_equal(actual.get(key),value,'result '+key)
 if set(actual)!=(set(expected_metadata)|{'cases'}):raise ValueError('result fields mismatch')
 if not isinstance(actual['cases'],list) or len(actual['cases'])!=1:raise ValueError('result case count mismatch')
 result_case=actual['cases'][0]
 if set(result_case)!={'id','templates_checked','survivors'}:raise ValueError('result case fields mismatch')
 require_equal(result_case['id'],case['id'],'result case id')
 require_equal(result_case['templates_checked'],spec['operation_cap'],'result templates_checked')
 if result_case['survivors']!=expected:raise ValueError('exact survivor/order mismatch')
 if any(not reencrypt(x,case['ciphertext']) for x in expected):raise ValueError('witness reencryption failed')
 counts={f:sum(x['family']==f for x in expected) for f in ('repeating_interrupted','progressive','autokey')}
 return {'schema_version':1,'status':'verified','operation_unit':'canonical_template_check','operations':actual['operations'],'operation_cap':spec['operation_cap'],'survivors':len(expected),'survivors_by_family':counts,'witnesses_reencrypted':len(expected),'unknowns':0,'calibration_gate_verified':True}
if __name__=='__main__':
 try:print(json.dumps(verify(Path(sys.argv[1]).resolve()),indent=2,sort_keys=True))
 except Exception as e:print('K4 verification failed: '+str(e),file=sys.stderr);raise SystemExit(1)
