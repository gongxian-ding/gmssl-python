
import binascii
from math import ceil, floor, log
from gmssl.sm3 import sm3_kdf, sm3_hash

from random import SystemRandom

import gmssl.optimized_field_elements as fq
import gmssl.optimized_curve as ec
import gmssl.optimized_pairing as ate

FAILURE = False
SUCCESS = True


def bitlen (n):
    return floor (log(n,2) + 1)

def i2sp (m, l):
    format_m = ('%x' % m).zfill(l*2).encode('utf-8')
    octets = [j for j in binascii.a2b_hex(format_m)]
    octets = octets[0:l]
    return ''.join (['%02x' %oc for oc in octets])

def fe2sp (fe):
    fe_str = ''.join (['%x' %c for c in fe.coeffs])
    if (len(fe_str) % 2) == 1:
        fe_str = '0' + fe_str
    return fe_str

def ec2sp (P):
    ec_str = ''.join([fe2sp(fe) for fe in P])
    return ec_str

def str2hexbytes (str_in):
    return [b for b in str_in.encode ('utf-8')]

def h2rf (i, z, n):
    l = 8 * ceil ((5*bitlen(n)) / 32)
    msg = i2sp(i,1).encode('utf-8')
    ha = sm3_kdf (msg+z, l)
    h = int (ha, 16)
    return (h % (n-1)) + 1

def setup (scheme):
    P1 = ec.G2
    P2 = ec.G1

    rand_gen = SystemRandom()
    s = rand_gen.randrange (ec.curve_order)

    if (scheme == 'sign'):
        Ppub = ec.multiply (P2, s)
        g = ate.pairing (P1, Ppub)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Ppub = ec.multiply (P1, s)
        g = ate.pairing (Ppub, P2)
    else:
        raise Exception('Invalid scheme')
        
    master_public_key = (P1, P2, Ppub, g)
    return (master_public_key, s)

def private_key_extract (scheme, master_public, master_secret, identity):
    P1 = master_public[0]
    P2 = master_public[1]

    user_id = sm3_hash (str2hexbytes (identity))
    m = h2rf (1, (user_id + '01').encode('utf-8'), ec.curve_order)
    m = master_secret + m
    if (m % ec.curve_order) == 0:
        return FAILURE
    m = master_secret * fq.prime_field_inv (m, ec.curve_order)

    if (scheme == 'sign'):
        Da = ec.multiply (P1, m)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Da = ec.multiply (P2, m)
    else:
        raise Exception('Invalid scheme')
    
    return Da

def public_key_extract (scheme, master_public, identity):
    P1, P2, Ppub, g = master_public
    
    user_id = sm3_hash (str2hexbytes (identity))
    h1 = h2rf (1, (user_id + '01').encode('utf-8'), ec.curve_order)

    if (scheme == 'sign'):
        Q = ec.multiply (P2, h1)
    elif (scheme == 'keyagreement') | (scheme == 'encrypt'):
        Q = ec.multiply (P1, h1)
    else:
        raise Exception('Invalid scheme')
        
    Q = ec.add (Q, Ppub)

    return Q
    
# scheme = 'sign'
def sign (master_public, Da, msg):
    g = master_public[3]
    
    rand_gen = SystemRandom()
    x = rand_gen.randrange (ec.curve_order)
    w = g**x
    
    msg_hash = sm3_hash (str2hexbytes(msg))
    z = (msg_hash + fe2sp(w)).encode('utf-8')
    h = h2rf (2, z, ec.curve_order)
    l = (x - h) % ec.curve_order

    S = ec.multiply (Da, l)
    return (h, S)

def verify (master_public, identity, msg, signature):
    (h, S) = signature
    
    if (h < 0) | (h >= ec.curve_order):
        return FAILURE
    if ec.is_on_curve (S, ec.b2) == False:
        return FAILURE

    Q = public_key_extract ('sign', master_public, identity)

    g = master_public[3]
    u = ate.pairing (S, Q)
    t = g**h
    wprime = u * t

    msg_hash = sm3_hash (str2hexbytes(msg))
    z = (msg_hash + fe2sp(wprime)).encode('utf-8')
    h2 = h2rf (2, z, ec.curve_order)

    if h != h2:
        return FAILURE
    return SUCCESS

# scheme = 'keyagreement'
def generate_ephemeral (master_public, identity):
    Q = public_key_extract ('keyagreement', master_public, identity)
    
    rand_gen = SystemRandom()
    x = rand_gen.randrange (ec.curve_order)
    R = ec.multiply (Q, x)
    
    return (x, R)
    
def generate_session_key (idA, idB, Ra, Rb, D, x, master_public, entity, l):
    P1, P2, Ppub, g = master_public

    if entity == 'A':
        R = Rb
    elif entity == 'B':
        R = Ra
    else:
        raise Exception('Invalid entity')
    
    g1 = ate.pairing (R, D)
    g2 = g**x
    g3 = g1**x

    if (entity == 'B'):
        (g1, g2) = (g2, g1)

    uidA = sm3_hash (str2hexbytes (idA))
    uidB = sm3_hash (str2hexbytes (idB))
    
    kdf_input = uidA + uidB
    kdf_input += ec2sp(Ra) + ec2sp (Rb)
    kdf_input += fe2sp(g1) + fe2sp(g2) + fe2sp(g3)
    
    sk = sm3_kdf (kdf_input.encode ('utf-8'), l)

    return sk

# encrypt

def kem_encap (master_public, identity, l):
    P1, P2, Ppub, g = master_public

    Q = public_key_extract ('encrypt', master_public, identity)

    rand_gen = SystemRandom()
    x = rand_gen.randrange (ec.curve_order)

    C1 = ec.multiply (Q, x)
    t = g**x

    uid = sm3_hash (str2hexbytes (identity))
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    k = sm3_kdf (kdf_input.encode ('utf-8'), l)

    return (k, C1)

def kem_decap (master_public, identity, D, C1, l):
    if ec.is_on_curve (C1, ec.b2) == False:
        return FAILURE

    t = ate.pairing (C1, D)

    uid = sm3_hash (str2hexbytes (identity))
    kdf_input = ec2sp(C1) + fe2sp(t) + uid
    k = sm3_kdf (kdf_input.encode ('utf-8'), l)

    return k

def kem_dem_enc (master_public, identity, message, v):
    hex_msg = str2hexbytes (message)
    mbytes = len(hex_msg)
    mbits = mbytes * 8
    
    k, C1 = kem_encap (master_public, identity, mbits + v)
    k = str2hexbytes (k)
    k1 = k[:mbytes]
    k2 = k[mbytes:]

    C2 = []
    for i in range (mbytes):
        C2.append (hex_msg[i] ^ k1[i])

    hash_input = C2 + k2
    C3 = sm3_hash(hash_input)[:int(v/8)]

    return (C1, C2, C3)

def kem_dem_dec (master_public, identity, D, ct, v):
    C1, C2, C3 = ct

    mbytes = len(C2)
    l = mbytes*8 + v
    k = kem_decap (master_public, identity, D, C1, l)

    k = str2hexbytes (k)
    k1 = k[:mbytes]
    k2 = k[mbytes:]

    hash_input = C2 + k2
    C3prime = sm3_hash(hash_input)[:int(v/8)]

    if C3 != C3prime:
        return FAILURE

    pt = []
    for i in range (mbytes):
        pt.append (chr (C2[i] ^ k1[i]))

    message = ''.join(pt)
        
    return message
