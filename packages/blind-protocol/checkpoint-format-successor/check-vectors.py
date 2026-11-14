#!/usr/bin/env python3
"""Independent Python byte codec for successor grammar and vector-used legacy fields.
No JS invocation, store access, signatures, reducer semantics or live capabilities.
CELL/INBOX Row.value remains the format's explicitly bounded predecessor byte blob.
"""
import hashlib,json,sys,platform
from pathlib import Path

fixed=lambda n:{'fixed':n}
B32=fixed(32)
B64=fixed(64)
blob=lambda n:{'bytes':[1,n]}
optional=lambda x:{'optional':x}
fields=lambda text:[tuple(x.split(':')) for x in text.split()]
legacy={}
legacy['admission']=fields('profileId:u16 schemeId:u16')+[['parameterHash',B32],['token',blob(4096)]]
legacy['binding']=[['version','u8'],['relayPublicKey',B32],['storeId',B32],['descriptorSequence','u64'],['descriptorHash',B32],['durabilityProfileId','u8'],['durabilityContinuityHash',B32],['durabilityProfileHash',B32],['restoreEvidenceHeadSequence','u64'],['restoreEvidenceHeadHash',B32],['externalCommitWitness',optional('witness')]]
legacy['witness']=[['version','u8']]+[[k,B32] for k in ['relayPublicKey','storeId','externalJournalId','durabilityContinuityHash','durabilityProfileHash']]+[['restoreEvidenceHeadSequence','u64'],['restoreEvidenceHeadHash',B32],['familyId','u8'],['operationId','u8'],['requestCommitment',B32],['resultCommitment',B32],['commitWalSequence','u64'],['commitWalHash',B32],['coveringFloorRevision','u64'],['coveringFloorHash',B32],['coveringFloorWalSequence','u64'],['coveringFloorWalHash',B32],['writerEpoch','u64'],['writerFenceTokenHash',B32],['externalLeaseRevision','u64'],['witnessedUnixMillis','u64'],['witnessPublicKey',B32],['signature',B64]]
legacy['blindPreparedAdmissionStoreV1']=[['version','u8'],['spendTag',B32],['requestCommitment',B32],['profileId','u16'],['schemeId','u16'],['parameterHash',B32],['resourceClass','u16'],['leaseClass','u8'],['costUnits','u64'],['walCommitRecord',blob(16384)]]
head=[['corePublicKey',B32],['fork','u64'],['length','u64'],['signedHeadHash',B32]]
legacy['coreMirrorRequestV1']=[['version','u8']]+head+[['leaseClass','u8'],['clientNonce',B32],['admission','admission']]
legacy['coreServeChallengeV1']=[['version','u8']]+head+[['blockIndices',{'array':'u64','max':16}],['clientNonce',B32],['admission',optional('admission')]]
legacy['blindCoreAckV1']=[['version','u8'],['relayBinding','binding']]+head+fields('observedAtEpoch:u32 leaseEpoch:u32 result:u8')+[['requestNonce',B32],['requestCommitment',B32],['signature',B64]]
legacy['blindCoreOpenReplicationRetrySnapshotV1']=[['version','u8'],['lifecycleState','u8'],['logicalRetryKey',B32],['spendTag',blob(128)],['requestCommitment',B32],['wireProfileHash',B32],['sessionClass','u8'],['clientNonce',B32],['parentSessionId',blob(256)],['controlChannelId','u64'],['parentChannelBinding',B32],['streamId','u64'],['maxSessionBytes','u64'],['idleMillis','u32'],['lifetimeMillis','u32'],['openedAtEpoch','u32'],['recordVirtualBucket','u16'],['resultBytes',optional(blob(16384))],['terminalReason',optional(blob(64))]]

def compact(n):
 if n<=252:return bytes([n])
 size,marker=(2,253) if n<=65535 else (4,254) if n<=4294967295 else (8,255)
 return bytes([marker])+n.to_bytes(size,'little')
def revive(x):
 if isinstance(x,list):return [revive(v) for v in x]
 if isinstance(x,dict):
  if '$bytes' in x:return bytes.fromhex(x['$bytes'])
  if '$u64' in x:return int(x['$u64'])
  return {k:revive(v) for k,v in x.items()}
 return x

def encode(t,v):
 if isinstance(t,str):
  if t in ['u8','u16','u32','u64','bool']:
   width=1 if t=='bool' else int(t[1:])//8
   assert type(v) is int and 0<=v<(2 if t=='bool' else 1<<(8*width))
   return v.to_bytes(width,'big')
  if t=='hash':assert len(v)==32 and any(v);return v
  table=defs.get(t,legacy.get(t));assert table is not None,t
  assert set(v)==set(k for k,_ in table)
  return b''.join(encode(child,v[k]) for k,child in table)
 if 'legacy' in t:return encode(t['legacy'],v)
 if 'optional' in t:return b'\0' if v is None else b'\1'+encode(t['optional'],v)
 if 'array' in t:assert len(v)<=t['max'];return compact(len(v))+b''.join(encode(t['array'],x) for x in v)
 if 'bytes' in t:assert t['bytes'][0]<=len(v)<=t['bytes'][1];return compact(len(v))+v
 if 'fixed' in t:assert len(v)==t['fixed'];return v
 if 'ascii' in t:assert v==t['ascii'].encode();return v
 if 'enum' in t:assert v in t['enum'];return bytes([v])
 if 'constant' in t:assert v==t['constant'];return encode(t['width'],v)
 raise AssertionError(t)

class Reader:
 def __init__(self,data):self.data=data;self.at=0
 def take(self,n):
  assert self.at+n<=len(self.data),'truncated'
  b=self.data[self.at:self.at+n];self.at+=n;return b
 def compact(self):
  marker=self.take(1)[0]
  if marker<=252:return marker
  size={253:2,254:4,255:8}[marker];v=int.from_bytes(self.take(size),'little')
  assert v>{253:252,254:65535,255:4294967295}[marker],'noncanonical compact'
  return v
 def read(self,t):
  if isinstance(t,str):
   if t in ['u8','u16','u32','u64','bool']:
    v=int.from_bytes(self.take(1 if t=='bool' else int(t[1:])//8),'big');assert t!='bool' or v<2;return v
   if t=='hash':v=self.take(32);assert any(v);return v
   return {k:self.read(child) for k,child in defs.get(t,legacy.get(t))}
  if 'legacy' in t:return self.read(t['legacy'])
  if 'optional' in t:
   n=self.take(1)[0];assert n in [0,1];return self.read(t['optional']) if n else None
  if 'array' in t:
   n=self.compact();assert n<=t['max'];return [self.read(t['array']) for _ in range(n)]
  if 'bytes' in t:
   n=self.compact();assert t['bytes'][0]<=n<=t['bytes'][1];return self.take(n)
  if 'fixed' in t:return self.take(t['fixed'])
  if 'ascii' in t:v=self.take(len(t['ascii']));assert v==t['ascii'].encode();return v
  if 'enum' in t:v=self.take(1)[0];assert v in t['enum'];return v
  if 'constant' in t:v=self.read(t['width']);assert v==t['constant'];return v
  raise AssertionError(t)

root=Path(sys.argv[1]);authority=(root/'format-authority-v2.json').read_bytes();defs=json.loads(authority)['definitions']
manifest=json.loads((root/'vectors-manifest.json').read_text())
assert hashlib.blake2b(b'hiverelay.blind.store-format-hash.v1'+len(authority).to_bytes(8,'big')+authority,digest_size=32).hexdigest()==manifest['formatHash']
vectors=revive(json.loads((root/'vectors/positive.json').read_text()))
for v in vectors:
 raw=(root/'vectors'/f"{v['id']}.bin").read_bytes()
 assert encode(v['type'],v['value'])==raw,v['id']
 r=Reader(raw);assert r.read(v['type'])==v['value'] and r.at==len(raw),v['id']
 assert hashlib.sha256(raw).hexdigest()==v['sha256']
 if v['domainHash'] is not None:
  domain=b'hiverelay.blind.checkpoint-snapshot.v2' if v['type']=='Snapshot' else b'hiverelay.blind.participant-authority.v1'
  assert hashlib.blake2b(domain+len(raw).to_bytes(8,'big')+raw,digest_size=32).digest()==v['domainHash']
print(json.dumps({'pass':True,'vectors':len(vectors),'python':sys.version,'platform':platform.platform(),'method':'independent encode/decode and BLAKE2b snapshot/participant hashes; nested CORE legacy fields independently encoded; family Row.value opaque per format; no authentication/reducer proof'}))
