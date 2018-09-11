import r2pipe
import sys

r2 = r2pipe.open(sys.argv[1])
classes = r2.cmdj("icj")

j = n = 0
for i,c in enumerate(classes):
    mtds = c['methods']
    if mtds != []:
        for m in mtds:
            j += 1
            for k,v in m.items():
                if k == 'flags':
                    if 'native' in v:
                        _m = m['name'].replace('.method.',';->')
                        print (_m)
                        n += 1
                        break
r2.quit()

sys.stderr.write(">> JNI [{} natives/{} methods/{} classes] <<\n".format(n,j,i))
