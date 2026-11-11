p='/home/sungwoo/FINAL/harness/ie/ie3_40g.sh'
lines=open(p).read().split('\n')
out=[]; i=0
while i<len(lines):
    L=lines[i]
    if 'taskset -c ${EVWD_CPUS[$idx]} bpftrace' in L:
        out.append('    sudo -n taskset -c ${EVWD_CPUS[$idx]} bpftrace --unsafe -e "tracepoint:syscalls:sys_enter_mprotect /pid==$srv && (args->prot & 2)/ { signal(9); } tracepoint:syscalls:sys_enter_openat /pid==$srv/ { if(str(args->filename)==\\"/proc/self/mem\\"){ signal(9); } }" > "$ROOT/t$idx/tamper_sentinel_ev.log" 2>&1 &')
        i+=2; continue
    if 'for i in $(seq 1 $N); do start_tenant $i || okN=NO; done' in L:
        out.append('  for i in $(seq 1 $N); do start_tenant $i || okN=NO; sleep 8; done')
        i+=1; continue
    out.append(L); i+=1
open(p,'w').write('\n'.join(out))
print('PATCHED')
