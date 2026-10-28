"""Explicit SYNTHETIC CDRC scenarios; no payload execution or external traffic."""
from datetime import timedelta
if __package__:
    from .m28_synthetic import windows,envelope
else:
    from m28_synthetic import windows,envelope


def win(index,at,code='4625',*,sysmon=False,host='SYNTH-M30-WINDOWS',user='SYNTHETIC\\analyst',
        ip='192.0.2.30',agent='930',guid='{00000000-0000-0000-0000-000000000930}'):
    raw = windows(index,at,code,sysmon=sysmon)
    raw['id'] = f'SYNTHETIC-M30-{index}'
    raw['agent']['id'] = agent
    raw['data']['win']['system']['computer'] = host
    data = raw['data']['win']['eventdata']
    data.update(targetUserName=user,subjectUserName=user,user=user,ipAddress=ip,sourceIp=ip,
                processGuid=guid,logonType='3')
    return raw


def auth(at,*,offset=0,**kwargs):
    return [win(offset+i,at+timedelta(seconds=i*10),'4625' if i<3 else '4624',**kwargs) for i in range(4)]


def ssh(index,at,success=False):
    raw = envelope(index,at)
    raw['id'] = f'SYNTHETIC-M30-SSH-{index}'
    raw['agent']['id'] = '930'
    raw.update(decoder={'name':'sshd'},location='/var/log/secure',
        full_log=f'<34>1 {at.isoformat()} SYNTH-M30-LINUX sshd {index} - - '+
            ('Accepted' if success else 'Failed')+' password for analyst from 192.0.2.30 port 50230 ssh2')
    return raw


def scenarios(at):
    office = win(101,at,'1',sysmon=True)
    office['data']['win']['eventdata'].update(image=r'C:\Windows\powershell.exe',parentImage=r'C:\Office\WINWORD.EXE')
    network = [win(201,at,'1',sysmon=True),win(202,at+timedelta(seconds=5),'3',sysmon=True)]
    cross = auth(at,offset=300)
    cross[-1]['agent']['id'] = 'another-endpoint'
    outside = auth(at,offset=400)
    outside[-1]['data']['win']['system']['systemTime'] = (at+timedelta(seconds=601)).isoformat()
    outside[-1]['timestamp'] = (at+timedelta(seconds=601)).isoformat()
    missing = auth(at,offset=500)
    for raw in missing:
        raw['data']['win']['eventdata'].pop('ipAddress')
        raw['data']['win']['eventdata'].pop('sourceIp')
    wrong_guid = [win(601,at,'1',sysmon=True),win(602,at+timedelta(seconds=5),'3',sysmon=True,
        guid='{00000000-0000-0000-0000-000000000999}')]
    return [
        ('windows-positive','SHADOW-WINDOWS-AUTH',auth(at),1,'POSITIVE'),
        ('windows-one-failure','SHADOW-WINDOWS-AUTH',[win(50,at),win(51,at+timedelta(seconds=5),'4624')],0,'NEGATIVE'),
        ('mixed-endpoint','SHADOW-WINDOWS-AUTH',cross,0,'NEGATIVE'),
        ('outside-window','SHADOW-WINDOWS-AUTH',outside,0,'NEGATIVE'),
        ('missing-source-ip','SHADOW-WINDOWS-AUTH',missing,0,'NEGATIVE'),
        ('ssh-positive','SHADOW-SSH-AUTH',[ssh(i,at+timedelta(seconds=i*10),i==3) for i in range(4)],1,'POSITIVE'),
        ('office-script','SHADOW-OFFICE-SCRIPT',[office],1,'POSITIVE'),
        ('process-network','SHADOW-PROCESS-NETWORK',network,1,'POSITIVE'),
        ('pid-reuse-different-guid','SHADOW-PROCESS-NETWORK',wrong_guid,0,'NEGATIVE'),
        ('account-privilege-context','SHADOW-ACCOUNT-PRIVILEGE',[win(701,at,'4720'),win(702,at+timedelta(seconds=5),'4672')],1,'POSITIVE'),
        ('duplicate-delivery','SHADOW-WINDOWS-AUTH',auth(at,offset=800)*2,1,'POSITIVE'),
        # A deliberate benign threshold match: report FP, not perfect efficacy.
        ('benign-retry-threshold','SHADOW-WINDOWS-AUTH',auth(at,offset=900),1,'NEGATIVE'),
        ('out-of-order','SHADOW-WINDOWS-AUTH',[auth(at,offset=1000)[i] for i in (3,0,2,1)],1,'POSITIVE'),
        ('cross-source-context','SHADOW-HOST-CONTEXT',[win(1101,at,'4624'),win(1102,at+timedelta(seconds=5),'1',sysmon=True)],1,'POSITIVE'),
        ('cross-source-different-host','SHADOW-HOST-CONTEXT',[win(1201,at,'4624'),win(1202,at+timedelta(seconds=5),'1',sysmon=True,host='SYNTH-OTHER-HOST')],0,'NEGATIVE'),
    ]
