import numpy as np
from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs
import qrcode
import random
import string
from pyzbar.pyzbar import decode
from PIL import Image
import csv

# asymmetric encryption
def encrypt(k, s):
    enc_str = ""
    for i, j in zip(s, str(k)):
        temp = str(ord(i) + ord(j)) + '_'
        enc_str = enc_str + temp
    return enc_str


def decrypt(k, p):
    dec_str = ""
    for i, j in zip(p.split("_")[:-1], str(k)):
        temp = chr(int(i) - ord(j))
        dec_str = dec_str + temp
    return dec_str

def array2bin(a):
    sr = ''
    for r in a:
        if r == 1:
            sr += '0'
        if r == -1:
            sr += '1'
    return sr

def challenge2str(C):
    C_1 = list()
    for m in range(16):
        for i in C[m]:
            if i == -1:
                C_1.append('0')
            else:
                C_1.append(str(i))
    return "".join(C_1)

def str2challenge(s):
    C = np.zeros((16,64),dtype=np.int)
    for m in range(16):
        for i in range(64):
            if s[64*m+i] == '0':
                C[m][i] = -1
            else:
                C[m][i] = 1
    return C

# initialize tag memory & server memory
tag_m = [["TempTx","S"]]
server_m = [["TempTx","Challenge","Response","S"]]
with open('tag_memory.csv', mode='w', encoding='utf-8-sig', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for line in tag_m:
        writer.writerow(line)

with open('server_memory.csv', mode='w', encoding='utf-8-sig', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for line in server_m:
        writer.writerow(line)

# -------------------------Setup Phase---------------------------

Tx = "tagID"
mk = "masterKey"
print("Setup phase start")
print("TagID Tx: "+Tx)
print("Masterkey mk: "+mk)

# generate S[1],C[1],TempTx[1]
chars = string.ascii_letters + string.digits
S = [random.choice(chars) for i in range(8)]
S = "".join(S)
print("For the first round, secret code S1: ")
print(S)
C = random_inputs(n=64, N=16, seed=int(random.random()))
TempTx = hash(S+(Tx+mk))
print("The challenges C1:")
print(C)
print("The TempTx1: ")
print(TempTx)

# PUF simulation
puf = XORArbiterPUF(n=64, k=8, seed=int(random.random()), noisiness=0)
rarray = puf.eval(C)
R = array2bin(rarray)
print("The response R1 from XOR PUF:")
print(R)
print("Writing in to memory...")

tag_1 = [[TempTx,S]]
server_1 = [[TempTx,challenge2str(C),R,S]]
with open('tag_memory.csv', mode='a', encoding='utf-8-sig', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for line in tag_1:
        writer.writerow(line)

with open('server_memory.csv', mode='a', encoding='utf-8-sig', newline='') as csvfile:
    writer = csv.writer(csvfile)
    for line in server_1:
        writer.writerow(line)

print("Setup Phase end\n")



#-------------------------Authentication Phase------------------
round = 0
while 1:
    input_str = input("Enter 1 for the next round of authentication and 2 for the end...")
    if input_str == '2':
        break
    if input_str == '1':
        round = round + 1
        TempTxi_t = ""
        TempTxi_s = ""
        Si_t = ""
        Si_s = ""
        Ci_s = ""
        Ci_t = ""
        Ri_t = ""
        Ri_s = ""
        with open('tag_memory.csv','r') as tag_memory:
            reader = csv.reader(tag_memory)
            result = list(reader)
            TempTxi_t = result[-1][0]
            Si_t = result[-1][1]
            print("In the "+str(round)+"-th round, TempTx"+str(round)+" from tag: ")
            print(TempTxi_t)

        with open('server_memory.csv','r') as server_memory:
            reader = csv.reader(server_memory)
            result = list(reader)
            TempTxi_s = result[-1][0]
            Ci_s = result[-1][1]
            Ri_s = result[-1][2]
            Si_s = result[-1][3]

        print("TempTx"+str(round)+" from server: ")
        print(TempTxi_s)
        if TempTxi_s != TempTxi_t:
            print("MSG1 - Wrong Temporary ID, stop authentication.")
            break
        else:
            print("MSG1 - Temporary ID verified, loading data...")

    # compute K
    Ki_s = hash(TempTxi_s+Si_s)
    print("The key K"+str(round)+": ")
    print(Ki_s)

    # encrypt challenges
    Di = []
    for i in range(64):
        Di.append(encrypt(Ki_s, Ci_s[i*16:(i+1)*16]))
    Hi_s = hash("".join(Di)+str(Ki_s))

    # verify Hi
    Ki_t = hash(TempTxi_t+Si_t)
    Hi_t = hash("".join(Di)+str(Ki_t))
    if Hi_t != Hi_s:
        print("MSG2 = Wrong hashcode, stop authentication")
        break
    else:
        print("MSG2 - Hashcode verified, generating data...")

    # PUF simulation
    for i in range(64):
        Ci_t=Ci_t+decrypt(Ki_t,Di[i])
    Ci_t = str2challenge(Ci_t)
    rarray = puf.eval(Ci_t)
    Ri_t = array2bin(rarray)
    print("Response R"+str(round)+":")
    print(Ri_t)
    X_t = encrypt(Ki_t,Ri_t)

    # generate QrCode
    print("Generating QR-Code, close the picture to continue...")
    qr = qrcode.QRCode(version=2, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10,
                       border=10, )
    qr.add_data(X_t)
    qr.make(fit=True)
    img = qr.make_image()
    img.show()
    img.save('qrcode'+str(round)+'.png')

    # Tag Generate next round data
    Si1_t=hash(Si_t)
    TempTxi1_t = hash(TempTxi_t+str(Si1_t))
    Ci1_t = random_inputs(n=64, N=16, seed=int(str(Si1_t)[1:4]))
    Ri1_t = puf.eval(Ci1_t)
    Ri1_t = array2bin(Ri1_t)
    Ki1_t = hash(Tx+str(Si1_t))
    Y = encrypt(Ki1_t,Ri1_t)
    Hi1_t = hash(str(X_t)+str(Ki_t)+str(Y))
    tag_i = [[TempTxi1_t,Si1_t]]
    with open('tag_memory.csv', mode='a', encoding='utf-8-sig', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for line in tag_i:
            writer.writerow(line)


    # Decrypt QrCode
    image = 'qrcode' + str(round) + '.png'
    img = Image.open(image)
    barcodes = decode(img)
    for barcode in barcodes:
        X_s = barcode.data.decode("utf-8")
        print("The data scanned from QR Code: ")
        print(X_s)

    # Server generate next round data
    Si1_s = hash(Si_s)
    TempTxi1_s = hash(TempTxi_s + str(Si1_s))
    Ci1_s = random_inputs(n=64, N=16, seed=int(str(Si1_s)[1:4]))
    Ki1_s = hash(Tx + str(Si1_s))
    Hi1_s = hash(X_s + str(Ki_s) + str(Y))
    if Hi1_s != Hi1_t:
        print("MSG3 - Wrong hashcode, stop authentication.")
        break
    else:
        print("MSG3 - Hashcode verified, decrypting data...")

    # Authentication
    decrypted_response = decrypt(Ki_s, X_s)
    print("The decrypted response from QR Code: ")
    print(decrypted_response)
    print("The response Ri stored in database:")
    print(Ri_s)
    if Ri_s != decrypted_response:
        print("Wrong response, authentication fail.")
        break
    else:
        print("Response verified, authentication success.")

    Ri1_s = decrypt(Ki1_s,Y)

    # Store new data
    server_i = [[TempTxi1_s,challenge2str(Ci1_s),Ri1_s,Si1_s]]
    with open('server_memory.csv', mode='a', encoding='utf-8-sig', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for line in server_i:
            writer.writerow(line)














