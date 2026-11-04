"""Per-case evidence recorder and Crystal bridge client."""
import json
import os
import pathlib
from . import core

class BridgeFailure(Exception):
    def __init__(self, response):
        self.response=response
        self.code=response.get('code')
        super().__init__(str(response))

class BlockedCase(Exception): pass

class Context:
    def __init__(self,config):
        self.config=config
        self.case=config['case']
        self.root=pathlib.Path(config['root'])
        self.evidence=pathlib.Path(config['evidence'])
        self.bridge_path=config.get('bridge')
        self.sequence=0
        self.notes=[]
        self.account_secrets_path=config.get('account_secrets')
        self.account_bridge_path=config.get('account_bridge')
        self._account_secrets=None

    def record(self,label,value):
        self.sequence+=1
        path=self.evidence/('%04d-%s.json'%(self.sequence,label))
        core.write_json(path,value)
        return value

    def batch(self,requests):
        if not self.bridge_path: raise BlockedCase('Crystal bridge did not compile; inspect stages/')
        self.sequence+=1
        prefix=self.evidence/('%04d-bridge'%self.sequence)
        core.write_json(prefix.with_suffix('.requests.json'),requests)
        result=core.command([self.bridge_path],prefix,self.config.get('inner_timeout',90),
                            cwd=self.root,isolate=False,stdin=(''.join(json.dumps(r,ensure_ascii=True)+'\n' for r in requests)).encode())
        if result['returncode']!=0 or result['timed_out']:
            raise AssertionError('Crystal bridge crashed, timed out, or could not start: '+str(result))
        lines=pathlib.Path(result['stdout']).read_text(encoding='utf-8').splitlines()
        if len(lines)!=len(requests): raise AssertionError('bridge response count mismatch')
        return [json.loads(line) for line in lines]

    def bridge(self,request,allow_error=False):
        response=self.batch([request])[0]
        if not response.get('ok'):
            if allow_error: return response
            raise BridgeFailure(response)
        return response if allow_error else response['value']


    def account_secrets(self):
        if not self.account_secrets_path:
            raise BlockedCase('local-account lab was not provisioned; rerun with -LocalAccounts')
        if self._account_secrets is None:
            from .windows_accounts import read_secret_file
            self._account_secrets=read_secret_file(pathlib.Path(self.account_secrets_path))
        return self._account_secrets

    def account(self,role):
        try:return self.account_secrets()['users'][role]
        except KeyError as exc:raise BlockedCase('missing local account role: '+role) from exc

    def bridge_as(self,role,request,allow_error=False):
        """Run one shard request under a real interactive-logon impersonation token.

        The password is supplied only through the child environment, which the
        evidence recorder never serializes. The request and result remain fully
        auditable.
        """
        if not self.bridge_path:
            raise BlockedCase('Crystal bridge did not compile')
        account=self.account(role)
        self.sequence+=1
        prefix=self.evidence/('%04d-bridge-impersonate-%s'%(self.sequence,role))
        effective=dict(request)
        effective['impersonate_user']=account['name']
        effective['impersonate_domain']=account.get('domain','.')
        core.write_json(prefix.with_suffix('.requests.json'),[effective])
        env=os.environ.copy()
        env['ACL_LAB_PASSWORD']=account['password']
        result=core.command([self.bridge_path],prefix,self.config.get('inner_timeout',90),
            cwd=self.root,env=env,isolate=False,stdin=(json.dumps(effective,ensure_ascii=True)+'\n').encode())
        self.record('bridge-impersonation-metadata',dict(role=role,user=account['name'],sid=account['sid'],
            returncode=result.get('returncode'),timed_out=result.get('timed_out')))
        if result['returncode']!=0 or result['timed_out']:
            raise AssertionError('impersonating Crystal bridge failed: '+str(result))
        lines=pathlib.Path(result['stdout']).read_text(encoding='utf-8').splitlines()
        if len(lines)!=1:raise AssertionError('impersonating bridge response count mismatch')
        response=json.loads(lines[0])
        if not response.get('ok'):
            if allow_error:return response
            raise BridgeFailure(response)
        return response if allow_error else response['value']

    def bridge_process_as(self,role,request,allow_error=False):
        """Launch the bridge with the account as its primary process token."""
        if not self.account_bridge_path:
            raise BlockedCase('alternate-account Crystal bridge was not prepared')
        from .windows_accounts import AccountProcessRunner
        account=self.account(role)
        self.sequence+=1
        prefix=self.evidence/('%04d-bridge-process-%s'%(self.sequence,role))
        core.write_json(prefix.with_suffix('.requests.json'),[request])
        result=AccountProcessRunner().run(account,pathlib.Path(self.account_bridge_path),self.root,
            (json.dumps(request,ensure_ascii=True)+'\n').encode(),prefix,self.config.get('inner_timeout',90))
        self.record('bridge-process-metadata',dict(role=role,user=account['name'],sid=account['sid'],
            returncode=result.returncode,timed_out=result.timed_out,elapsed_seconds=result.elapsed_seconds,
            launch_error=result.launch_error,stderr=result.stderr))
        if result.launch_error or result.timed_out or result.returncode!=0:
            raise AssertionError('alternate-account process bridge failed: '+str(result))
        lines=result.stdout.splitlines()
        if len(lines)!=1:raise AssertionError('alternate-account process response count mismatch')
        response=json.loads(lines[0])
        if not response.get('ok'):
            if allow_error:return response
            raise BridgeFailure(response)
        return response if allow_error else response['value']

    def fixture(self,name='fixture',directory=False):
        path=self.root/name
        if directory: path.mkdir()
        else: path.write_bytes(b'ACL lab synthetic data\n')
        return path

    def equal(self,actual,expected,label):
        if actual!=expected:
            self.record('mismatch',dict(label=label,actual=actual,expected=expected))
            raise AssertionError(label)

    def require(self,condition,label):
        if not condition: raise AssertionError(label)
