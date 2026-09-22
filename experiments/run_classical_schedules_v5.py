#!/usr/bin/env python3
"""Generate and run the hidden-seed Milestone 11 calibration."""

import hashlib, json, os, shutil, subprocess, sys, time
from datetime import datetime, timezone
from itertools import combinations
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=ROOT/'experiments/CLASSICAL-SCHEDULES-0005.json'
CRIB_POS=list(range(21,34))+list(range(63,74))

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def dump(path,obj): path.write_text(json.dumps(obj,indent=2,sort_keys=True)+"\n")
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
  if raw['family']!='autokey' and raw.get('phase') is None:raw['phase']=raw['period']-1
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

def event(obj):
 with (ROOT/'experiments/registry.jsonl').open('a') as f:f.write(json.dumps(obj,sort_keys=True)+'\n')
def now(): return datetime.now(timezone.utc).isoformat()

def main():
 if len(sys.argv)!=3: raise SystemExit('usage: run_classical_schedules.py SEED_FILE RUN_DIR')
 seed_path=Path(sys.argv[1]); run=(ROOT/sys.argv[2]).resolve()
 if not run.is_relative_to(ROOT/'results') or run.exists(): raise SystemExit('run directory must be new and below results/')
 spec=json.loads(SPEC.read_text()); seed=seed_path.read_bytes()
 if len(seed)!=32 or hashlib.sha256(seed).hexdigest()!=spec['seed_commitment_sha256']: raise SystemExit('seed does not match frozen commitment')
 for name,digest in spec['evidence_file_hashes'].items():
  if sha(ROOT/name)!=digest: raise SystemExit(f'frozen hash mismatch: {name}')
 subprocess.run(['cargo','build','--release','--locked'],cwd=ROOT,check=True)
 binary=ROOT/'target/release/kryptos-research';binary_hash=sha(binary)
 if binary_hash!=spec['expected_binary_sha256']:raise SystemExit('compiled binary hash mismatch')
 run.mkdir(parents=True); run_id=str(run.relative_to(ROOT)); event({'experiment_id':spec['experiment_id'],'run_id':run_id,'status':'started','at':now()})
 start=time.monotonic(); public,private=generate(seed)
 request={'schema_version':1,'cases':public,'operation_cap':spec['calibration_template_check_cap']}; dump(run/'public-cases.json',request)
 private_tmp=Path('/tmp')/f'm11-private-{os.getpid()}.json'; dump(private_tmp,private)
 manifest={'schema_version':1,'experiment_id':spec['experiment_id'],'run_id':run_id,'spec_sha256':sha(SPEC),'seed_commitment_sha256':spec['seed_commitment_sha256'],'evidence_file_hashes':spec['evidence_file_hashes'],'implementation_paths':spec['implementation_paths'],'public_case_count':160,'operation_unit':'canonical_template_check','operation_cap':spec['calibration_template_check_cap'],'wall_time_cap_seconds':spec['wall_time_cap_seconds'],'binary_sha256':binary_hash}; dump(run/'manifest.json',manifest)
 shutil.copy2(binary,run/'attacker-binary')
 with (run/'attacker-output.json').open('wb') as out,(run/'attacker.stderr').open('wb') as err:
  proc=subprocess.run([binary,'classical-schedules',run/'public-cases.json'],cwd=ROOT,stdout=out,stderr=err,timeout=spec['wall_time_cap_seconds'])
 if proc.returncode: raise SystemExit('attacker failed')
 if sha(binary)!=binary_hash:raise SystemExit('binary changed during attack')
 attack=json.loads((run/'attacker-output.json').read_text())
 if attack['operations']!=spec['calibration_template_check_cap']:raise SystemExit('operation count/cap mismatch')
 shutil.move(private_tmp,run/'controller-private.json'); dump(run/'seed-reveal.json',{'seed_hex':seed.hex(),'commitment_sha256':hashlib.sha256(seed).hexdigest()})
 verify=subprocess.run([sys.executable,ROOT/'verification/verify_classical_schedules_v5.py',run],cwd=ROOT,capture_output=True,text=True)
 (run/'verification.stderr').write_text(verify.stderr)
 if verify.returncode: raise SystemExit('verification failed: '+verify.stderr)
 (run/'verification.json').write_text(verify.stdout)
 elapsed=time.monotonic()-start
 artifacts={p.name:sha(p) for p in sorted(run.iterdir()) if p.name!='completion.json'}
 if elapsed>spec['wall_time_cap_seconds']:raise SystemExit('wall cap exceeded after final artifact hashing')
 completion={'schema_version':1,'experiment_id':spec['experiment_id'],'run_id':run_id,'status':'completed','wall_seconds':elapsed,'artifact_sha256':artifacts,'calibration_passed':True,'operation_unit':'canonical_template_check','operations':attack['operations'],'operation_cap':spec['calibration_template_check_cap'],'binary_sha256':binary_hash,'k4_models_evaluated':0}
 dump(run/'completion.json',completion); event({'experiment_id':spec['experiment_id'],'run_id':run_id,'status':'completed','at':now(),'completion_sha256':sha(run/'completion.json')})
 print(json.dumps(completion,indent=2))
if __name__=='__main__': main()
