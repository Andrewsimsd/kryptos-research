#!/usr/bin/env python3
"""Independently verify a complete Milestone 11 calibration run."""

import hashlib, json, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
from itertools import combinations
CRIB_POS=list(range(21,34))+list(range(63,74))

# Independent domain enumeration and case regeneration; no controller module is imported.
class Rng:
 def __init__(self,seed): self.seed=seed; self.n=0; self.buf=b''
 def u32(self):
  if len(self.buf)<4:
   self.buf+=hashlib.sha256(self.seed+self.n.to_bytes(8,'big')).digest(); self.n+=1
  v=int.from_bytes(self.buf[:4],'big'); self.buf=self.buf[4:]; return v
 def pick(self,n): return self.u32()%n
 def letters(self,n): return ''.join(chr(65+self.pick(26)) for _ in range(n))

def coordinate_maps():
 out={}
 subsets=[()] + [(x,) for x in (4,35,66)] + list(combinations((4,35,66),2))
 for period in range(1,33):
  for resets in subsets:
   m=tuple((i-max((r for r in resets if r<=i),default=0))%period for i in range(97))
   out.setdefault(m,(period,list(resets)))
 return [(m,*out[m]) for m in sorted(out)]

def templates():
 out=[]
 for m,p,r in coordinate_maps():
  for eq in ('vigenere_or_variant','beaufort'): out.append({'family':'repeating_interrupted','map':m,'period':p,'resets':r,'equation':eq})
 for p in range(1,33):
  for d in range(1,26):
   for eq in ('vigenere_or_variant','beaufort'): out.append({'family':'progressive','period':p,'increment':d,'equation':eq})
 for p in range(1,33):
  for fb in ('plaintext','ciphertext'):
   for eq in ('vigenere','beaufort','variant_beaufort'): out.append({'family':'autokey','period':p,'feedback':fb,'equation':eq})
 return out

def tid(t):
 if t['family']=='repeating_interrupted': return f"coord:{t['period']:02}:"+'-'.join(map(str,t['resets']))+f":{t['equation']}:"+','.join(map(str,t['map']))
 if t['family']=='progressive': return f"progressive:{t['period']:02}:{t['increment']:02}:{t['equation']}"
 return f"autokey:{t['period']:02}:{t['feedback']}:{t['equation']}"

def encrypt(plain,t,seed):
 keys=[]; cipher=[]
 for i,p in enumerate(map(lambda x:ord(x)-65,plain)):
  if t['family']=='repeating_interrupted': k=seed[t['map'][i]]
  elif t['family']=='progressive': k=(seed[i%t['period']]+(i//t['period'])*t['increment'])%26
  elif i<t['period']: k=seed[i]
  elif t['feedback']=='plaintext': k=ord(plain[i-t['period']])-65
  else: k=ord(cipher[i-t['period']])-65
  if t['equation'] in ('vigenere','vigenere_or_variant'): c=(p+k)%26
  elif t['equation']=='variant_beaufort': c=(p-k)%26
  else: c=(k-p)%26
  keys.append(k); cipher.append(chr(65+c))
 return ''.join(cipher)

def compatible(case,t):
 """Return whether some seed assignment fits the supplied cribs."""
 fixed=[None]*t['period']
 if t['family'] in ('repeating_interrupted','progressive'):
  for crib in case['cribs']:
   i=crib['position'];c=ord(case['ciphertext'][i])-65;p=ord(crib['plaintext'])-65
   key=(c+p)%26 if t['equation']=='beaufort' else (c-p)%26
   if t['family']=='repeating_interrupted':j=t['map'][i]
   else:j=i%t['period'];key=(key-(i//t['period'])*t['increment'])%26
   if fixed[j] is not None and fixed[j]!=key:return False
   fixed[j]=key
  return True
 expr=[];n=t['period']
 for i,ch in enumerate(case['ciphertext']):
  c=ord(ch)-65
  if i<n:e=(-1,i,c) if t['equation']=='vigenere' else ((1,i,c) if t['equation']=='variant_beaufort' else (1,i,-c%26))
  elif t['feedback']=='ciphertext':
   k=ord(case['ciphertext'][i-n])-65;e=(0,0,((k-c)%26 if t['equation']=='beaufort' else ((c+k)%26 if t['equation']=='variant_beaufort' else (c-k)%26)))
  else:
   a,j,b=expr[i-n]
   e=(-a,j,(c-b)%26) if t['equation']=='vigenere' else ((a,j,(c+b)%26) if t['equation']=='variant_beaufort' else (a,j,(b-c)%26))
  expr.append(e)
 for crib in case['cribs']:
  p=ord(crib['plaintext'])-65;a,j,b=expr[crib['position']]
  if a==0:
   if b!=p:return False
  else:
   key=(p-b)%26 if a==1 else (b-p)%26
   if fixed[j] is not None and fixed[j]!=key:return False
   fixed[j]=key
 return True

def raw_models():
 subsets=[[],[4],[35],[66],[4,35],[4,66],[35,66]]; out=[]
 for i in range(40):
  out.append({'family':'repeating_interrupted','period':(1 if i==0 else 32 if i==1 else 2+(i*7)%31),'resets':subsets[i%7],'phase':0 if i%2==0 else None,'equation':('vigenere','variant_beaufort','beaufort')[i%3]})
 for i in range(40):
  d=(0 if i==0 else 1 if i%5==0 else 25 if i%7==0 else 1+(i*11)%25)
  out.append({'family':'progressive','period':(1 if i==0 else 32 if i==1 else 2+(i*5)%31),'phase':0 if i%2==0 else None,'origin':0 if i%2==0 else 25,'increment':d,'equation':('vigenere','variant_beaufort','beaufort')[i%3]})
 for i in range(40):
  out.append({'family':'autokey','period':1 if i==0 else 32 if i==1 else 2+(i*3)%31,'feedback':('plaintext','ciphertext')[i%2],'equation':('vigenere','beaufort','variant_beaufort')[i%3]})
 for raw in out:
  if raw.get('phase') is None: raw['phase']=raw['period']-1
 return out

def raw_encrypt(plain,raw,seed):
 cipher=[]; resets=raw.get('resets',[])
 for i,ch in enumerate(plain):
  p=ord(ch)-65
  if raw['family']=='repeating_interrupted':
   start=max((r for r in resets if r<=i),default=0);k=seed[((i-start)+raw['phase'])%raw['period']]
  elif raw['family']=='progressive':k=(seed[(i+raw['phase'])%raw['period']]+(i//raw['period'])*raw['increment']+raw['origin'])%26
  elif i<raw['period']:k=seed[i]
  elif raw['feedback']=='plaintext':k=ord(plain[i-raw['period']])-65
  else:k=ord(cipher[i-raw['period']])-65
  c=(p+k)%26 if raw['equation']=='vigenere' else ((p-k)%26 if raw['equation']=='variant_beaufort' else (k-p)%26);cipher.append(chr(65+c))
 return ''.join(cipher)

def canonicalize(raw,seed):
 if raw['family']=='autokey':
  t={k:raw[k] for k in ('family','period','feedback','equation')};return t,seed
 sign=-1 if raw['equation']=='variant_beaufort' else 1;eq='beaufort' if raw['equation']=='beaufort' else 'vigenere_or_variant'
 if raw['family']=='progressive' and raw['increment']%26:
  d=(sign*raw['increment'])%26; effective=[(sign*(seed[(j+raw['phase'])%raw['period']]+raw['origin']))%26 for j in range(raw['period'])]
  return {'family':'progressive','period':raw['period'],'increment':d,'equation':eq},effective
 resets=raw.get('resets',[]);m=tuple((i-max((r for r in resets if r<=i),default=0))%raw['period'] for i in range(97))
 reps={x:(p,r) for x,p,r in coordinate_maps()};rep_period,rep_resets=reps[m]
 raw_keys=[]
 for i in range(97):
  if raw['family']=='progressive':k=(seed[(i+raw['phase'])%raw['period']]+raw['origin'])%26
  else:k=seed[(m[i]+raw['phase'])%raw['period']]
  raw_keys.append((sign*k)%26)
 effective=[None]*rep_period
 rep_map=next(x for x,p,r in coordinate_maps() if p==rep_period and r==rep_resets and x==m)
 for i,k in enumerate(raw_keys):
  j=rep_map[i]
  if effective[j] is not None and effective[j]!=k:raise RuntimeError('canonical coordinate mismatch')
  effective[j]=k
 effective=[x or 0 for x in effective]
 return {'family':'repeating_interrupted','map':m,'period':rep_period,'resets':rep_resets,'equation':eq},effective

def generate(seed):
 rng=Rng(seed); raws=raw_models(); public=[]; private=[]; canonical=[]
 for i,raw in enumerate(raws):
  plain=rng.letters(97); seedv=[rng.pick(26) for _ in range(raw['period'])]
  ciphertext=raw_encrypt(plain,raw,seedv);t,effective=canonicalize(raw,seedv)
  if ciphertext!=encrypt(plain,t,effective):raise RuntimeError('raw/canonical reencryption mismatch')
  case={'id':f'positive-{i:03}','ciphertext':ciphertext,'cribs':[{'position':p,'plaintext':plain[p]} for p in CRIB_POS]}
  public.append(case);canonical.append(t);private.append({'id':case['id'],'cohort':'positive','planted_template_id':tid(t),'plaintext':plain,'raw_model':raw,'raw_seed':seedv,'canonical_seed':effective})
 negative=0
 for source_index,(source,t) in enumerate(zip(public[:120],canonical)):
  if negative==40:break
  found=None
  for j in range(len(CRIB_POS)):
   old=ord(source['cribs'][j]['plaintext'])-65
   for delta in range(1,26):
    candidate=json.loads(json.dumps(source));candidate['cribs'][j]['plaintext']=chr(65+(old+delta)%26)
    if not compatible(candidate,t):found=(candidate,j);break
   if found:break
  if found:
   case,j=found;case['id']=f'tamper-{negative:03}';public.append(case)
   private.append({'id':case['id'],'cohort':'tamper','planted_template_id':private[source_index]['planted_template_id'],'source_id':source['id'],'tamper_position':case['cribs'][j]['position']});negative+=1
 if negative!=40:raise RuntimeError(f'only {negative} planted-template-excluding tamper cases could be generated')
 return public,private


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
 expected_request={'schema_version':1,'cases':regen_public,'operation_cap':spec['calibration_template_check_cap']}
 if public!=expected_request or private!=regen_private:raise ValueError('public/private regeneration mismatch')
 if manifest['spec_sha256']!=hashlib.sha256((ROOT/'experiments'/f"{manifest['experiment_id']}.json").read_bytes()).hexdigest():raise ValueError('spec hash mismatch')
 if manifest['implementation_paths']!=spec['implementation_paths'] or manifest['evidence_file_hashes']!=spec['evidence_file_hashes']:raise ValueError('frozen path/hash set mismatch')
 for name,digest in spec['evidence_file_hashes'].items():
  if hashlib.sha256((ROOT/name).read_bytes()).hexdigest()!=digest:raise ValueError('frozen file mismatch: '+name)
 if manifest['binary_sha256']!=spec['expected_binary_sha256'] or hashlib.sha256((run/'attacker-binary').read_bytes()).hexdigest()!=spec['expected_binary_sha256']:raise ValueError('attacker binary mismatch')
 if manifest['operation_unit']!='canonical_template_check' or manifest['operation_cap']!=spec['calibration_template_check_cap']:raise ValueError('operation declaration mismatch')
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
 positives=[x for x in private if x['cohort']=='positive']; public_by={x['id']:x for x in public['cases']}
 for truth in positives:
  raw=truth['raw_model'];canonical,effective=canonicalize(raw,truth['raw_seed']);cipher=raw_encrypt(truth['plaintext'],raw,truth['raw_seed'])
  if cipher!=public_by[truth['id']]['ciphertext'] or cipher!=encrypt(truth['plaintext'],canonical,effective):raise ValueError('raw/canonical reencryption mismatch: '+truth['id'])
  if tid(canonical)!=truth['planted_template_id'] or effective!=truth['canonical_seed']:raise ValueError('canonicalization mismatch: '+truth['id'])
 aliases=[x['raw_model'] for x in positives]
 if any(x.get('phase',0) not in (0,x['period']-1) for x in aliases):raise ValueError('phase is not a registered endpoint')
 alias_coverage={
  'phases':sorted({x.get('phase',0) for x in aliases if x.get('phase',0) in (0,31)}),
  'origins':sorted({x['origin'] for x in aliases if x.get('origin') is not None}),
  'equations':sorted({x['equation'] for x in aliases}),
  'increments_including_alias':sorted({x['increment'] for x in aliases if x.get('increment') is not None and x['increment'] in (0,1,25)}),
  'reset_subsets':sorted({tuple(x.get('resets',[])) for x in aliases if x['family']=='repeating_interrupted'}),
 }
 expected_alias={'phases':[0,31],'origins':[0,25],'equations':['beaufort','variant_beaufort','vigenere'],'increments_including_alias':[0,1,25],'reset_subsets':[(),(4,),(4,35),(4,66),(35,),(35,66),(66,)]}
 if alias_coverage!=expected_alias:raise ValueError('raw alias coverage incomplete: '+repr(alias_coverage))
 if attack['operations']!=spec['calibration_template_check_cap'] or checks!=spec['calibration_template_check_cap']:raise ValueError('operation accounting mismatch')
 return {'schema_version':1,'status':'passed','positive_retained':retained,'positive_total':120,'tamper_excluded':excluded,'tamper_total':40,'unknown_cases':0,'operation_unit':'canonical_template_check','operations':checks,'operation_cap':spec['calibration_template_check_cap'],'witnesses_reencrypted':witnesses,'coverage':coverage,'raw_model_coverage':alias_coverage,'raw_models_reencrypted_and_canonicalized':120,'k4_models_evaluated':0}

def main():
 try:print(json.dumps(verify(Path(sys.argv[1]).resolve()),indent=2,sort_keys=True));return 0
 except Exception as e:print('classical schedule verification failed: '+str(e),file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
