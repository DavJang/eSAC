import re,sys
none={}; esac={}
for ln in open("/home/sungwoo/intra_clean.txt"):
    if not ln.startswith("KEY"): continue
    d=dict(re.findall(r"(\w+)=([^\s]+)",ln))
    if d.get("mode")=="none":
        none[(d["dir"],d["core"],d["pay"],d["cc"])]=int(d["deliv"])
    elif d.get("mode")=="esac" and d.get("case")=="pass":
        esac[(d["dir"],d["layer"],d["core"],d["pay"],d["cc"])]=(int(d["deliv"]),int(d.get("offered",0)),int(d.get("insp_hits",0)))
def M(x): return f"{x/1e6:.2f}"
SATP={"1":8000,"2":16000,"4":32000}
print("\n================ PAYLOAD SWEEP (saturate=100%) : deliv Mpps, eSAC vs none ================")
for dr in ["rx","tx"]:
  for lay in ["l4","l7"]:
    print(f"\n--- intra {dr.upper()} {lay.upper()} ---")
    print(f"{pay:>5} | " + " | ".join(f"c{c}: none / eSAC / %" for c in [1,2,4]))
    for pay in ["64","256","512","1024","1400"]:
      cells=[]
      for c in ["1","2","4"]:
        cc=str(SATP[c]); n=none.get((dr,c,pay,cc)); e=esac.get((dr,lay,c,pay,cc))
        if n and e: cells.append(f"{M(n)}/{M(e[0])}/{100*e[0]//n}%")
        else: cells.append("  -  ")
      print(f"{pay:>5} | " + " | ".join(f"{x:>18}" for x in cells))
print("\n================ LOAD SWEEP (1400B) : offered->deliv Mpps ================")
for dr in ["rx","tx"]:
  for lay in ["l4","l7"]:
    for c in ["1","2","4"]:
      ladder=sorted({k[4] for k in esac if k[0]==dr and k[1]==lay and k[2]==c and k[3]=="1400"}, key=int)
      if not ladder: continue
      print(f"\n--- intra {dr.upper()} {lay.upper()} c{c} (offered=none send, deliv=eSAC vs none) ---")
      for cc in ladder:
        n=none.get((dr,c,"1400",cc)); e=esac.get((dr,lay,c,"1400",cc))
        if e:
          offe=e[1]; nd=none.get((dr,c,"1400",cc),0)
          print(f"  cc={cc:>6} offered~{M(offe)}M  none_deliv={M(nd) if nd else -}  eSAC_deliv={M(e[0])}  ({100*e[0]//nd if nd else 0}%)  hits={e[2]//1000}k")
