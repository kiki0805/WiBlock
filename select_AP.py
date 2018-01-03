with open('BSSs', 'r') as bss_f:
    import re
    bss_pat = re.compile('\w{2}:\w{2}:\w{2}:\w{2}:\w{2}:\w{2}')
    BSSs = bss_f.read()
    BSSs = bss_pat.findall(BSSs)
    bss_f.close()

with open('SSIDs', 'r') as ssid_f:
    SSIDs = ssid_f.read()
    SSIDs = SSIDs.split('SSID: ')
    final_SSID = []
    for SSID in SSIDs:
        SSID = SSID.strip()
        if SSID != '':
            final_SSID.append(SSID)
    ssid_f.close()

assert len(BSSs) == len(final_SSID)

SSID_set = set()
AP_list = []
count = 1
for i in range(len(BSSs)):
    if final_SSID[i] in SSID_set:
        continue
    print(str(count) + '\t', end='')
    print(final_SSID[i])
    SSID_set.add(final_SSID[i])
    AP_list.append((BSSs[i], final_SSID[i]))
    count += 1


selection = input('\nPlease choose one AP to connect...(Input the number)\n')
chose = AP_list[eval(selection) - 1][1]
print('Connect to {}...'.format(chose))

import os
os.system('iw dev wlan0 connect' + chose)


