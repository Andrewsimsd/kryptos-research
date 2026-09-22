"""Focused tests for the independent classical-schedule verifier."""
import unittest
import json
from pathlib import Path
import shutil
import tempfile

from verify_classical_k4_v3 import verify as verify_k4
from verify_classical_schedules_v5 import canonicalize, coordinate_maps, encrypt, raw_encrypt, raw_models, solve, reencrypt

class ClassicalVerifierTests(unittest.TestCase):
 def test_independent_coordinate_census(self): self.assertEqual(len(coordinate_maps()),200)
 def test_free_seed_witness_reencrypts(self):
  t={'family':'progressive','period':32,'increment':25,'equation':'vigenere_or_variant'}
  case={'id':'x','ciphertext':'B'*97,'cribs':[{'position':21,'plaintext':'A'}]}
  survivor=solve(case,t);self.assertIsNotNone(survivor);self.assertTrue(reencrypt(survivor,case['ciphertext']))
 def test_contradictory_repeating_residue_is_rejected(self):
  m=tuple(i%2 for i in range(97));t={'family':'repeating_interrupted','map':m,'period':2,'resets':[],'equation':'vigenere_or_variant'}
  case={'id':'x','ciphertext':'AAA','cribs':[{'position':0,'plaintext':'A'},{'position':2,'plaintext':'B'}]}
  self.assertIsNone(solve(case,t))
 def test_variant_progressive_sign_and_origin_canonicalize_exactly(self):
  raw={'family':'progressive','period':5,'phase':4,'origin':25,'increment':1,'equation':'variant_beaufort'};seed=[1,2,3,4,5];plain='A'*97
  canonical,effective=canonicalize(raw,seed)
  self.assertEqual(canonical['increment'],25)
  self.assertEqual(raw_encrypt(plain,raw,seed),encrypt(plain,canonical,effective))
 def test_zero_increment_progressive_becomes_coordinate_map(self):
  raw={'family':'progressive','period':32,'phase':31,'origin':25,'increment':0,'equation':'variant_beaufort'};seed=list(range(26))+list(range(6));plain='B'*97
  canonical,effective=canonicalize(raw,seed)
  self.assertEqual(canonical['family'],'repeating_interrupted')
  self.assertEqual(raw_encrypt(plain,raw,seed),encrypt(plain,canonical,effective))
 def test_verifier_does_not_import_controller_scientific_logic(self):
  source=Path('verification/verify_classical_schedules_v5.py').read_text()
  self.assertNotIn('from run_classical',source)
  self.assertNotIn('import run_classical',source)
 def test_autokey_raw_models_do_not_have_phase(self):
  models=raw_models()
  self.assertTrue(all('phase' not in x for x in models if x['family']=='autokey'))
  for family in ('progressive','repeating_interrupted'):
   family_models=[x for x in models if x['family']==family]
   self.assertTrue(all(x['phase'] in (0,x['period']-1) for x in family_models))
   self.assertTrue(any(x['phase']==0 for x in family_models))
   self.assertTrue(any(x['phase']==x['period']-1 and x['period']>1 for x in family_models))
 def test_full_k4_verifier_rejects_registered_metadata_mutations(self):
  source=Path('results/CLASSICAL-SCHEDULES-K4-0003/run-001')
  with tempfile.TemporaryDirectory(prefix='.verify-k4-',dir='results') as directory:
   run=Path(directory).resolve()
   for path in source.iterdir():shutil.copy2(path,run/path.name)
   manifest_path=run/'manifest.json';result_path=run/'result.json'
   manifest=json.loads(manifest_path.read_text());manifest['run_id']=str(run.relative_to(Path.cwd().resolve()));manifest_path.write_text(json.dumps(manifest,indent=2,sort_keys=True)+'\n')
   verify_k4(run)
   mutations=(
    ('manifest operation unit',manifest_path,lambda x:x.__setitem__('operation_unit','equation_check')),
    ('manifest calibration path',manifest_path,lambda x:x.__setitem__('calibration_completion','results/CLASSICAL-SCHEDULES-0004/run-001/completion.json')),
    ('result canonical templates',result_path,lambda x:x.__setitem__('canonical_templates',2191)),
    ('result raw tuples',result_path,lambda x:x.__setitem__('raw_parameter_tuples',65855)),
    ('result template counts',result_path,lambda x:x['template_counts'].__setitem__('autokey',191)),
    ('result templates checked',result_path,lambda x:x['cases'][0].__setitem__('templates_checked',2191)),
   )
   for label,path,mutate in mutations:
    with self.subTest(label=label):
     original=json.loads(path.read_text());changed=json.loads(path.read_text());mutate(changed);path.write_text(json.dumps(changed,indent=2,sort_keys=True)+'\n')
     with self.assertRaises(ValueError):verify_k4(run)
     path.write_text(json.dumps(original,indent=2,sort_keys=True)+'\n')
if __name__=='__main__':unittest.main()
