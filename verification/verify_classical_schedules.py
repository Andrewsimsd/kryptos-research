#!/usr/bin/env python3
"""Independently verify a complete Milestone 11 calibration run."""

import hashlib, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'experiments'))
from run_classical_schedules import generate, templates, tid  # controller reproduction only

def load(path): return json.loads(path.read_text())
def val(x): return ord(x)-65
def sub(a,b): return (a-b)%26
def dec(c,k,eq): return (k-c)%26 if eq=='beaufort' else ((c+k)%26 if eq=='variant_beaufort' else (c-k)%26)
def mult(f): return str(26**f)

def decrypt_autokey(cipher,seed,t):
 p=[]; keys=[]; n=t['period']
 for i,ch in enumerate(cipher):
  if i<n:k=seed[i]
  elif t['feedback']=='ciphertext':k=val(cipher[i-n])
  else:k=p[i-n]
  keys.append(k);p.append(dec(val(ch),k,t['equation']))
 return p,keys

def solve(case,t):
 n=t['period']; fixed=[None]*n
 if t['family'] in ('repeating_interrupted','progressive'):
  for crib in case['cribs']:
   i=crib['position']; c=val(case['ciphertext'][i]); p=val(crib['plaintext'])
   key=(c+p)%26 if t['equation']=='beaufort' else sub(c,p)
   if t['family']=='repeating_interrupted': j=t['map'][i]
   else:j=i%n;key=sub(key,((i//n)*t['increment'])%26)
   if fixed[j] is not None and fixed[j]!=key:return None
   fixed[j]=key
  seed=[x or 0 for x in fixed]
  if t['family']=='repeating_interrupted':keys=[seed[t['map'][i]] for i in range(len(case['ciphertext']))]
  else:keys=[(seed[i%n]+(i//n)*t['increment'])%26 for i in range(len(case['ciphertext']))]
  plain=[dec(val(c),k,'beaufort' if t['equation']=='beaufort' else 'vigenere') for c,k in zip(case['ciphertext'],keys)]
 else:
  expr=[]
  for i,ch in enumerate(case['ciphertext']):
   c=val(ch)
   if i<n:
    e=(-1,i,c) if t['equation']=='vigenere' else ((1,i,c) if t['equation']=='variant_beaufort' else (1,i,(-c)%26))
   elif t['feedback']=='ciphertext':e=(0,0,dec(c,val(case['ciphertext'][i-n]),t['equation']))
   else:
    a,j,b=expr[i-n]
    if t['equation']=='vigenere':e=(-a,j,sub(c,b))
    elif t['equation']=='variant_beaufort':e=(a,j,(c+b)%26)
    else:e=(a,j,sub(b,c))
   expr.append(e)
  for crib in case['cribs']:
   p=val(crib['plaintext']);a,j,b=expr[crib['position']]
   if a==0:
    if b!=p:return None
   else:
    key=sub(p,b) if a==1 else sub(b,p)
    if fixed[j] is not None and fixed[j]!=key:return None
    fixed[j]=key
  seed=[x or 0 for x in fixed];plain,keys=decrypt_autokey(case['ciphertext'],seed,t)
 if any(plain[x['position']]!=val(x['plaintext']) for x in case['cribs']):return None
 family=t['family']; eq=t['equation']; free=sum(x is None for x in fixed)
 out={'template_id':tid(t),'family':family,'equation':eq,'period':n,'fixed_seed':fixed,'free_seed_components':free,'concrete_stream_multiplicity':mult(free),'witness_seed':''.join(chr(65+x) for x in seed),'witness_plaintext':''.join(chr(65+x) for x in plain),'witness_key':''.join(chr(65+x) for x in keys)}
 if family=='progressive':out['increment']=t['increment']
 if family=='repeating_interrupted' and t['resets']:out['resets']=t['resets']
 if family=='autokey':out['feedback']=t['feedback']
 return out

def reencrypt(s,cipher):
 p=map(val,s['witness_plaintext']);k=map(val,s['witness_key']);eq=s['equation'];out=[]
 for a,b in zip(p,k):
  if eq in ('vigenere','vigenere_or_variant'):v=(a+b)%26
  elif eq=='variant_beaufort':v=(a-b)%26
  else:v=(b-a)%26
  out.append(chr(65+v))
 return ''.join(out)==cipher

def verify(run):
 manifest=load(run/'manifest.json');spec=load(ROOT/'experiments'/f"{manifest['experiment_id']}.json");public=load(run/'public-cases.json');private=load(run/'controller-private.json');attack=load(run/'attacker-output.json');reveal=load(run/'seed-reveal.json')
 seed=bytes.fromhex(reveal['seed_hex'])
 if hashlib.sha256(seed).hexdigest()!=spec['seed_commitment_sha256']:raise ValueError('seed commitment mismatch')
 regen_public,regen_private=generate(seed)
 expected_request={'schema_version':1,'cases':regen_public,'operation_cap':350720}
 if public!=expected_request or private!=regen_private:raise ValueError('public/private regeneration mismatch')
 if manifest['implementation_paths']!=spec['implementation_paths'] or set(manifest['evidence_file_hashes'])!=set(spec['evidence_file_hashes']):raise ValueError('frozen path set mismatch')
 for name,digest in spec['evidence_file_hashes'].items():
  if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:raise ValueError('frozen file mismatch: '+name)
 all_t=templates(); attack_by={x['id']:x for x in attack['cases']}; truth={x['id']:x for x in private}
 retained=excluded=checks=witnesses=0
 for case in public['cases']:
  expected=[x for t in all_t if (x:=solve(case,t)) is not None];expected.sort(key=lambda x:x['template_id']);actual=attack_by[case['id']]['survivors']
  if actual!=expected:raise ValueError('exact survivor/order mismatch: '+case['id'])
  if any(not reencrypt(x,case['ciphertext']) for x in actual):raise ValueError('witness reencryption failed')
  planted=truth[case['id']]['planted_template_id'];ids={x['template_id'] for x in actual}
  if truth[case['id']]['cohort']=='positive':
   if planted not in ids:raise ValueError('planted template lost: '+case['id'])
   retained+=1
  else:
   if planted in ids:raise ValueError('tamper retained planted template: '+case['id'])
   excluded+=1
  checks+=len(all_t);witnesses+=len(actual)
 # Coverage is derived from planted positive IDs and controller truth.
 planted_ids={x['planted_template_id'] for x in private if x['cohort']=='positive'}
 planted=[t for t in all_t if tid(t) in planted_ids]
 coverage={
  'families':sorted({t['family'] for t in planted}),
  'period_boundaries':sorted({t['period'] for t in planted if t['period'] in (1,32)}),
  'progressive_increment_boundaries':sorted({t.get('increment') for t in planted if t.get('increment') in (1,25)}),
  'autokey_equations':sorted({t['equation'] for t in planted if t['family']=='autokey'}),
  'feedback':sorted({t['feedback'] for t in planted if t['family']=='autokey'}),
 'reset_counts':sorted({len(t['resets']) for t in planted if t['family']=='repeating_interrupted'}),
 }
 required={'families':['autokey','progressive','repeating_interrupted'],'period_boundaries':[1,32],'progressive_increment_boundaries':[1,25],'autokey_equations':['beaufort','variant_beaufort','vigenere'],'feedback':['ciphertext','plaintext'],'reset_counts':[0,1,2]}
 if coverage!=required:raise ValueError('boundary coverage incomplete: '+repr(coverage))
 aliases=[x['raw_alias'] for x in private if x['cohort']=='positive']
 if any(x['phase'] not in (0,x['period']-1) for x in aliases):raise ValueError('phase alias is not a registered endpoint')
 alias_coverage={
  'phases':sorted({x['phase'] for x in aliases if x['phase'] in (0,31)}),
  'origins':sorted({x['origin'] for x in aliases if x['origin'] is not None}),
  'equations':sorted({x['equation'] for x in aliases}),
  'increments_including_alias':sorted({x['increment'] for x in aliases if x['increment'] is not None and x['increment'] in (0,1,25)}),
  'reset_subsets':sorted({tuple(x['resets']) for x in aliases}),
 }
 expected_alias={'phases':[0,31],'origins':[0,25],'equations':['beaufort','variant_beaufort','vigenere','vigenere_or_variant'],'increments_including_alias':[0,1,25],'reset_subsets':[(),(4,),(4,35),(4,66),(35,),(35,66),(66,)]}
 if alias_coverage!=expected_alias:raise ValueError('raw alias coverage incomplete: '+repr(alias_coverage))
 if attack['operations']!=350720 or checks!=350720:raise ValueError('operation accounting mismatch')
 return {'schema_version':1,'status':'passed','positive_retained':retained,'positive_total':120,'tamper_excluded':excluded,'tamper_total':40,'unknown_cases':0,'canonical_template_checks':checks,'witnesses_reencrypted':witnesses,'coverage':coverage,'raw_alias_coverage':alias_coverage,'k4_models_evaluated':0}

def main():
 try:print(json.dumps(verify(Path(sys.argv[1]).resolve()),indent=2,sort_keys=True));return 0
 except Exception as e:print('classical schedule verification failed: '+str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
