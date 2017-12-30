import time
import random  
import string  

while 1:
	chr_num = ''  
	for i in range(12):  
	    str_num = str(random.choice('abcdef' + string.digits))  
	    chr_num += str_num  
	
	fake_MAC = ''
	for chr in chr_num:
		if len(fake_MAC) in [2, 5, 8, 11, 14]:
			fake_MAC += ':'
		fake_MAC += chr
	choice1 = 'wlan0: STA %s IEEE 802.11: associated' % fake_MAC
	choice2 = 'wlan0: STA %s IEEE 802.11: disassociated' % fake_MAC
	choice3 = 'Something else(ignored)'
	print(random.choice([choice1, choice2, choice3]))
	time.sleep(random.randint(1,3))
