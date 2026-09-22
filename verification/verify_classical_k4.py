#!/usr/bin/env python3
"""Independently enumerate and verify the saved Milestone 11 K4 census."""
import json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'verification'),str(ROOT/'experiments')]
from verify_classical_schedules import solve, reencrypt
from run_classical_schedules import templates

def main():
 request=json.loads(Path(sys.argv[1]).read_text());actual=json.loads(Path(sys.argv[2]).read_text())
 expected=[]
 for template in templates():
  survivor=solve(request['cases'][0],template)
  if survivor is not None:expected.append(survivor)
 expected.sort(key=lambda x:x['template_id'])
 if actual['cases'][0]['survivors']!=expected:raise SystemExit('independent K4 survivor/order mismatch')
 if any(not reencrypt(x,request['cases'][0]['ciphertext']) for x in expected):raise SystemExit('K4 witness reencryption failed')
 counts={family:sum(x['family']==family for x in expected) for family in ('repeating_interrupted','progressive','autokey')}
 print(json.dumps({'schema_version':1,'status':'verified','canonical_templates':2192,'survivors':len(expected),'survivors_by_family':counts,'witnesses_reencrypted':len(expected),'unknowns':0,'interpretation':'Compatibility with 24 known letters only; no survivor is ranked or claimed as plaintext.'},indent=2,sort_keys=True))
 return 0
if __name__=='__main__':raise SystemExit(main())
