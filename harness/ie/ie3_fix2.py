p='/home/sungwoo/eSACfinal/harness/ie/ie3_40g.sh'
s=open(p).read()
old='  for i in $(seq 1 $N); do start_tenant $i || okN=NO; sleep 8; done'
new='  okN=YES; for i in $(seq 1 $N); do start_tenant $i || okN=NO; sleep 8; done'
assert old in s, 'anchor not found'
s=s.replace(old,new)
open(p,'w').write(s)
print('OKN_FIXED')
