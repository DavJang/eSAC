import re
none={}; esac={}
for ln in open("/home/sungwoo/inter_clean.txt"):
    if not ln.startswith("KEY"): continue
    d=dict(re.findall(r"(\w+)=([^\s]+)",ln))
    if d.get("mode")=="none":
        none[(d["dir"],d["core"],d["pay"],d["cc"])]=int(d["deliv"])
    elif d.get("mode")=="esac" and d.get("case")=="pass":
        esac[(d["dir"],d["layer"],d["core"],d["pay"],d["cc"])]=(int(d["deliv"]),int(d.get("offered","0")),int(d.get("insp_hits","0")))
def M(x): return "%.2f"%(x/1e6)
def pct(e,n): return str(100*e//n)+"%" if n else "-"
SATP={"1":"8000","2":"16000","4":"32000"}
print("\n==== PAYLOAD SWEEP @ saturate : none / eSAC (Mpps) / %none ====")
for dr in ["rx","tx"]:
  for lay in ["l4","l7"]:
    print("\n--- inter %s %s ---"%(dr.upper(),lay.upper()))
    print("%5s | %-20s | %-20s | %-20s"%("pay","c1 none/eSAC/%","c2 none/eSAC/%","c4 none/eSAC/%"))
    for pay in ["64","256","512","1024","1400"]:
      row=[]
      for c in ["1","2","4"]:
        cc=SATP[c]; n=none.get((dr,c,pay,cc)); e=esac.get((dr,lay,c,pay,cc))
        row.append("%s/%s/%s"%(M(n) if n else "-", M(e[0]) if e else "-", pct(e[0],n) if (e and n) else "-"))
      print("%5s | %-20s | %-20s | %-20s"%(pay,row[0],row[1],row[2]))
print("\n==== LOAD SWEEP @1400B : offered->eSAC deliv vs none (Mpps) ====")
for dr in ["rx","tx"]:
  for lay in ["l4","l7"]:
    for c in ["1","2","4"]:
      ladder=sorted({k[4] for k in esac if k[0]==dr and k[1]==lay and k[2]==c and k[3]=="1400"}, key=int)
      if not ladder: continue
      print("\n--- inter %s %s c%s ---"%(dr.upper(),lay.upper(),c))
      for cc in ladder:
        n=none.get((dr,c,"1400",cc)); e=esac.get((dr,lay,c,"1400",cc))
        if not e: continue
        print("  cc=%6s offered~%sM  none=%s  eSAC=%s  (%s)  hits=%dk"%(
            cc, M(e[1]), M(n) if n else "-", M(e[0]), pct(e[0],n) if n else "-", e[2]//1000))
