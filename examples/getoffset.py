from roputils import *
from resource import setrlimit, RLIMIT_CORE, RLIM_INFINITY

fpath = sys.argv[1]

setrlimit(RLIMIT_CORE, (RLIM_INFINITY, RLIM_INFINITY))

p = Proc(fpath)
p.write(p32(200))
p.write(Pattern.create(200))
p.read()
p.close()

p = Popen(['gdb', fpath, 'core', '--batch', '-ex', 'x/wx $sp'], stdin=PIPE, stdout=PIPE)
data = p.stdout.readlines()
retaddr = data[len(data)-1].split(':')[1].strip()
print Pattern.offset(retaddr)
p.wait()

os.system('rm core*')
