import time
import random  
import string  

associated = []
disassociated = []

while 1:
    chr_num = ''  
    for i in range(12):  
        str_num = str(random.choice('abcdef' + string.digits))  
        chr_num += str_num  

    fake_MAC = ''
    for char in chr_num:
        if len(fake_MAC) in [2, 5, 8, 11, 14]:
            fake_MAC += ':'
        fake_MAC += char

    choices = []
    choice1 = 'wlan0: STA %s IEEE 802.11: associated' % fake_MAC
    choices.append(choice1)
    choice2_MAC = ''
    choice2 = ''
    if associated != []:
        choice2_MAC = random.choice(associated)
        choice2 = 'wlan0: STA %s IEEE 802.11: disassociated' % choice2_MAC
        choices.append(choice2)
    choices.append('Something else(ignored)')
    random_choice = random.choice(choices)
    print(random_choice)

    if random_choice == choice1:
        associated.append(fake_MAC)
    elif random_choice == choice2:
        associated.remove(choice2_MAC)
        disassociated.append(choice2_MAC)
    else:
        pass

    time.sleep(random.randint(1,3))


