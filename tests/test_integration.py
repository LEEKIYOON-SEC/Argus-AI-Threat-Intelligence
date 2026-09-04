#!/usr/bin/env python3
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))
for k in ("GH_TOKEN","SUPABASE_URL","SUPABASE_KEY","SLACK_WEBHOOK_URL","GEMINI_API_KEY"):
    os.environ.setdefault(k,"test")
import pipeline  # noqa: E402
from backfill_signals import reconcile  # noqa: E402
from backfill_cvss import apply_scores  # noqa: E402

STORE={}
class DB:
    def get_cve(self,c): return STORE.get(c)
    def upsert_cve(self,p): STORE.setdefault(p["id"],{}).update(p); return True

ok=[]
def chk(c,m): ok.append((c,m)); print(("  OK   " if c else "  FAIL ")+m)

print("── silent 백필은 notifier 가 None 이어도 안 터진다 ──")
st={"id":"C1","is_kev":True,"cvss":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N","cwe":[]}
out=pipeline.process(dict(st), DB(), None, silent=True)
chk(out.status=="tracked", f"status={out.status}")
chk("kev" in STORE["C1"]["last_alert_state"]["fired_triggers"], "발화 이력은 기록된다")
chk("last_alert_at" not in STORE["C1"], "last_alert_at 은 안 남긴다")

print("\n── backfill_cvss 결과가 다음 fast-lane 에서 살아남는다 ──")
STORE.clear()
old={"id":"C2","cvss":0.0,"cvss_vector":"N/A","cvss_scores":{},"tier":"T0",
     "is_vulncheck_kev":True,"fired_triggers":["vulncheck_kev"]}
fixed=apply_scores(old, {"3.0":(7.5,"CVSS:3.0/AV:N/AC:L/PR:N/UI:N")})
chk(fixed["cvss"]==7.5, f"백필이 7.5 로 채운다 ({fixed['cvss']})")
STORE["C2"]={"id":"C2","last_alert_state":fixed}
fresh={"id":"C2","cvss":0.0,"cvss_vector":"N/A","cvss_version":"","cvss_scores":{},
       "cwe":[],"title":"T","is_vulncheck_kev":True}
pipeline.process(fresh, DB(), None, silent=True)
chk(STORE["C2"]["last_alert_state"]["cvss"]==7.5,
    f"fast-lane 재처리 뒤에도 7.5 ({STORE['C2']['last_alert_state']['cvss']})")

print("\n── backfill_signals 결과가 다음 회차에 알림을 안 낸다 ──")
STORE.clear()
stored={"id":"C3","ssvc":{"exploitation":"active"},"tier":"T3","fired_triggers":[]}
STORE["C3"]={"id":"C3","last_alert_state":reconcile(stored)}
class Slack:
    calls=0
    def send_alert(self,*a,**k):
        Slack.calls+=1; return True
fresh={"id":"C3","ssvc":{"exploitation":"active"},"ssvc_exploitation":"active",
       "cwe":[],"cvss":0.0,"cvss_vector":"N/A","title":"T"}
pipeline.process(fresh, DB(), Slack())
chk(Slack.calls==0, f"정합 뒤에는 알림 0회 (실제 {Slack.calls})")
chk(STORE["C3"]["last_alert_state"]["tier"]=="T0", "등급은 T0 유지")

print("\n── SSVC 가 사라진 회차에도 등급이 안 내려간다 ──")
gone={"id":"C3","cwe":[],"cvss":0.0,"cvss_vector":"N/A","title":"T"}
pipeline.process(gone, DB(), Slack())
chk(STORE["C3"]["last_alert_state"]["tier"]=="T0",
    f"이월로 T0 유지 ({STORE['C3']['last_alert_state']['tier']})")

print(f"\n{'전부 통과' if all(c for c,_ in ok) else '실패 있음'}")
sys.exit(0 if all(c for c,_ in ok) else 1)
