import time
import random
import string
f=open('re.txt')
associated=[]
while 1:
    inf=raw_input()
    if len(inf)==52:
        associated.append(inf[11:28])
        print('new STA add:')
        print(associated)
        print('\n')
    if len(inf)==55:
        mac=inf[11:28]
        if mac in associated:
            associated.remove(mac)
            print('disassociated: '+mac)
            print(associated)
            print('\n')
    time.sleep(random.randint(1,3))
