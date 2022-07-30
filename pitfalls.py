import SM2
from SM3 import SM3
from random import randint
import time

def ctint(a):
    return int(a,16)
def Precompute(Z_list):  #
    return  SM3(Z_list[0]+Z_list[1]+Z_list[2]+Z_list[3]+Z_list[4]+Z_list[5]+Z_list[6]+Z_list[7])

def ECDSA_sign(M,k,n,d):
    x,y=SM2.ecc_multiply(k,G)
    e=SM3(M)
    e=int(e,16)
    r= int(x,16)  % n
    s= ((e+r* ctint(d)) * SM2.findModInverse(ctint(k),n))  %n
    return hex(r)[2:],hex(s)[2:]

def Sign(G,n,M,dA,Z):
    M_=Z+M
    e=SM3(M_)
    k=randint(1,n)
    k = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
    k=int(k,16)
    kG=SM2.ecc_multiply(hex(k)[2:],G)   #坐标点,列表十六进制形式  椭圆曲线上的运算全为字符串,数据类型需要转化
    #print("kGx",(kG[0]))
    #print("kGy",int(kG[1],16))
    r=(int(e,16)+int(kG[0],16))  % n
    if r==0 or r+k==n:
        Sign(G, n, M, dA, Z)
        return 0
    s=(SM2.findModInverse(1+int(dA,16),n) * (k-r*int(dA,16))) % n
    if s==0:
        Sign(G, n, M, dA, Z)
        return 0

    return [hex(r)[2:],hex(s)[2:]]
def verify(M,r,s,Z,PA):
    e=SM3(Z+M)
    t=int(r,16)+int(s,16) %n
    #print("t:",t)
    lll=((1+int(dA,16))*int(s,16) + int(r,16)*int(dA,16)) %n
    #print("lll",hex(lll))
    x1,y1=SM2.ecc_multiply(hex(lll)[2:],G)
    #print("x1",x1)
    #x1,y1=SM2.ecc_diff_add(SM2.ecc_multiply(s,G),SM2.ecc_multiply(hex(t)[2:],PA))
    R=(int(e,16)+int(x1,16)) % n
    #print(hex(R)[2:])
    #print(r)
    if hex(R)[2:]==r:
        print("验证成功")
def Lk_to_Ld(k,r,s,n):
    return hex((SM2.findModInverse(int(r,16)+int(s,16),n) * (int(k,16)-int(s,16))) % n)[2:]

def REk_to_Ld(r1,s1,r2,s2,n):
    r1=ctint(r1)
    s1=ctint(s1)
    r2=ctint(r2)
    s2=ctint(s2)
    lll=(s2-s1)%n
    rrr=SM2.findModInverse(s1-s2+r1-r2,n)
    return hex((lll*rrr)  % n)[2:]

def rkduser(k,r1,s1,r2,s2):  # reusing k by different users
    k=ctint(k)
    r1=ctint(r1)
    s1=ctint(s1)
    r2=ctint(r2)
    s2=ctint(s2)
    Arkdu=(((k-s1)%n) * SM2.findModInverse(s1+r1,n)) % n
    Brkdu=(((k-s2)%n) * SM2.findModInverse(s2+r2,n)) % n
    return hex(Arkdu)[2:],hex(Brkdu)[2:]

def sdkECDSA(M,n,r1,s1,r2,s2):
    r1 = ctint(r1)
    s1 = ctint(s1)
    r2 = ctint(r2)
    s2 = ctint(s2)
    hashM=ctint(SM3(M))
    lll=(s1*s2 - hashM)  % n
    rrr=SM2.findModInverse((r1-s1*s2-s1*r2)%n,n)   % n
    return hex((lll*rrr) % n)[2:]

Gx = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
Gy = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
xA = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
yA = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
k = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F"
n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
n=int(n,16)
a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"  # 模数60275702009245096385686171515219896416297121499402250955537857683885541941187
dA = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"  # 58724923310756937240092846960887528428411685443607809329868213582531823290246
ENTLa = "1649AB77A00637BD5E2Eaaa83FBF353534AA7F7CB89463F208DDBC2920BB0DA0"
IDa = "1649AB7fff0637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"
Zlist = [ENTLa, IDa, a, b, Gx, Gy, xA, yA]
Z = Precompute(Zlist)
ecc = [a, b, p]  # 确定一个椭圆曲线
G = [Gx, Gy]  # 基点
PA=SM2.ecc_multiply(dA,G)

#******泄露k导致泄露私钥 dA = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"
# M="202000460052"
# r,s=Sign(G, n, M, dA, Z)
# lk_to_ld=Lk_to_Ld(k,r,s,n)
# print("计算私钥:",lk_to_ld)

#******重复使用一个k,导致泄露私钥 dA = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"
# M1="202000"
# M2="460052"
# r1,s1=Sign(G, n, M1, dA, Z)
# r2,s2=Sign(G, n, M2, dA, Z)
# reusing_d=REk_to_Ld(r1,s1, r2, s2, n)
# print("计算私钥:",reusing_d)

#*******不同用户使用同一个k,
# M1="202000"
# M2="460052"
# AK="1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"
# BK="787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
# r1,s1=Sign(G, n, M1, AK, Z)
# r2,s2=Sign(G, n, M2, BK, Z)
# temp1,temp2=rkduser(k,r1, s1, r2, s2)
# print("计算私钥A:",temp1)
# print("计算私钥B:",temp2)

#******same d and k with ECDSA  dA = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0"
M="202000460052"
r1,s1=ECDSA_sign(M,k,n,dA)
r2,s2=Sign(G, n, M, dA, Z)
temp=sdkECDSA(M, n, r1, s1, r2, s2)
print("计算私钥:",temp)




