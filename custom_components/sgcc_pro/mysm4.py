import base64
import binascii
import json
from array import array
from struct import pack, unpack

# from Crypto.Cipher import AES
# from Crypto.Hash import MD5
from gmssl import func, sm3
from gmssl.sm2 import CryptSM2

# from gmssl.sm3 import sm3_hash as SM3_gmssl
# from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

_SM4_FK = array("L", [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC])
_SM4_CK = array(
    "L",
    [
        0x00070E15,
        0x1C232A31,
        0x383F464D,
        0x545B6269,
        0x70777E85,
        0x8C939AA1,
        0xA8AFB6BD,
        0xC4CBD2D9,
        0xE0E7EEF5,
        0xFC030A11,
        0x181F262D,
        0x343B4249,
        0x50575E65,
        0x6C737A81,
        0x888F969D,
        0xA4ABB2B9,
        0xC0C7CED5,
        0xDCE3EAF1,
        0xF8FF060D,
        0x141B2229,
        0x30373E45,
        0x4C535A61,
        0x686F767D,
        0x848B9299,
        0xA0A7AEB5,
        0xBCC3CAD1,
        0xD8DFE6ED,
        0xF4FB0209,
        0x10171E25,
        0x2C333A41,
        0x484F565D,
        0x646B7279,
    ],
)
_SM4_S_BOX = bytes(
    [
        0xD6,
        0x90,
        0xE9,
        0xFE,
        0xCC,
        0xE1,
        0x3D,
        0xB7,
        0x16,
        0xB6,
        0x14,
        0xC2,
        0x28,
        0xFB,
        0x2C,
        0x05,
        0x2B,
        0x67,
        0x9A,
        0x76,
        0x2A,
        0xBE,
        0x04,
        0xC3,
        0xAA,
        0x44,
        0x13,
        0x26,
        0x49,
        0x86,
        0x06,
        0x99,
        0x9C,
        0x42,
        0x50,
        0xF4,
        0x91,
        0xEF,
        0x98,
        0x7A,
        0x33,
        0x54,
        0x0B,
        0x43,
        0xED,
        0xCF,
        0xAC,
        0x62,
        0xE4,
        0xB3,
        0x1C,
        0xA9,
        0xC9,
        0x08,
        0xE8,
        0x95,
        0x80,
        0xDF,
        0x94,
        0xFA,
        0x75,
        0x8F,
        0x3F,
        0xA6,
        0x47,
        0x07,
        0xA7,
        0xFC,
        0xF3,
        0x73,
        0x17,
        0xBA,
        0x83,
        0x59,
        0x3C,
        0x19,
        0xE6,
        0x85,
        0x4F,
        0xA8,
        0x68,
        0x6B,
        0x81,
        0xB2,
        0x71,
        0x64,
        0xDA,
        0x8B,
        0xF8,
        0xEB,
        0x0F,
        0x4B,
        0x70,
        0x56,
        0x9D,
        0x35,
        0x1E,
        0x24,
        0x0E,
        0x5E,
        0x63,
        0x58,
        0xD1,
        0xA2,
        0x25,
        0x22,
        0x7C,
        0x3B,
        0x01,
        0x21,
        0x78,
        0x87,
        0xD4,
        0x00,
        0x46,
        0x57,
        0x9F,
        0xD3,
        0x27,
        0x52,
        0x4C,
        0x36,
        0x02,
        0xE7,
        0xA0,
        0xC4,
        0xC8,
        0x9E,
        0xEA,
        0xBF,
        0x8A,
        0xD2,
        0x40,
        0xC7,
        0x38,
        0xB5,
        0xA3,
        0xF7,
        0xF2,
        0xCE,
        0xF9,
        0x61,
        0x15,
        0xA1,
        0xE0,
        0xAE,
        0x5D,
        0xA4,
        0x9B,
        0x34,
        0x1A,
        0x55,
        0xAD,
        0x93,
        0x32,
        0x30,
        0xF5,
        0x8C,
        0xB1,
        0xE3,
        0x1D,
        0xF6,
        0xE2,
        0x2E,
        0x82,
        0x66,
        0xCA,
        0x60,
        0xC0,
        0x29,
        0x23,
        0xAB,
        0x0D,
        0x53,
        0x4E,
        0x6F,
        0xD5,
        0xDB,
        0x37,
        0x45,
        0xDE,
        0xFD,
        0x8E,
        0x2F,
        0x03,
        0xFF,
        0x6A,
        0x72,
        0x6D,
        0x6C,
        0x5B,
        0x51,
        0x8D,
        0x1B,
        0xAF,
        0x92,
        0xBB,
        0xDD,
        0xBC,
        0x7F,
        0x11,
        0xD9,
        0x5C,
        0x41,
        0x1F,
        0x10,
        0x5A,
        0xD8,
        0x0A,
        0xC1,
        0x31,
        0x88,
        0xA5,
        0xCD,
        0x7B,
        0xBD,
        0x2D,
        0x74,
        0xD0,
        0x12,
        0xB8,
        0xE5,
        0xB4,
        0xB0,
        0x89,
        0x69,
        0x97,
        0x4A,
        0x0C,
        0x96,
        0x77,
        0x7E,
        0x65,
        0xB9,
        0xF1,
        0x09,
        0xC5,
        0x6E,
        0xC6,
        0x84,
        0x18,
        0xF0,
        0x7D,
        0xEC,
        0x3A,
        0xDC,
        0x4D,
        0x20,
        0x79,
        0xEE,
        0x5F,
        0x3E,
        0xD7,
        0xCB,
        0x39,
        0x48,
    ]
)
_SM4_S_BOX_FAST = array("H")
for byte1 in _SM4_S_BOX:  # 构造两字节的S盒变换表
    byte1 <<= 8
    _SM4_S_BOX_FAST.extend(byte1 | byte2 for byte2 in _SM4_S_BOX)


def _T_key(ka):  # 用于生成圈密钥的T'变换
    B = _SM4_S_BOX_FAST[ka >> 16] << 16 | _SM4_S_BOX_FAST[ka & 0xFFFF]  # S盒变换
    return (B ^ (B << 13 | B >> 19) ^ (B << 23 | B >> 9)) & 0xFFFFFFFF  # L线性变换


def _T(x):  # T变换
    B = _SM4_S_BOX_FAST[x >> 16] << 16 | _SM4_S_BOX_FAST[x & 0xFFFF]  # S盒变换
    return (
        B
        ^ (B << 2 | B >> 30)
        ^ (B << 10 | B >> 22)
        ^ (B << 18 | B >> 14)
        ^ (B << 24 | B >> 8)
    ) & 0xFFFFFFFF  # L线性变换


def _one_round(rK, X):  # T变换
    X0, X1, X2, X3 = X
    for rk in rK:
        X0, X1, X2, X3 = X1, X2, X3, X0 ^ _T(X1 ^ X2 ^ X3 ^ rk)
    return [X3, X2, X1, X0]


def _ecb_base(rK, X):
    for i in range(0, len(X), 4):  # 4个字为一组
        X[i : i + 4] = _one_round(rK, X[i : i + 4])
    return X


def _cbc_enc(rK, iv, X):
    for i in range(0, len(X), 4):
        iv = X[i : i + 4] = _one_round(rK, [X[i + j] ^ iv[j] for j in range(4)])
    return X


def _cbc_dec(rK, iv, X):
    for i in range(0, len(X), 4):
        next_iv = X[i : i + 4]
        X[i : i + 4], iv = (
            list(map(lambda x, y: x ^ y, _one_round(rK, X[i : i + 4]), iv)),
            next_iv,
        )
    return X


# bytes转数组（4个字节为一字）
def byte2array(data):
    return list(unpack(">%dI" % (len(data) >> 2), data))


# 数组转bytes
def array2byte(data):
    return pack(">%dI" % (len(data)), *data)


# 填充成16字节倍数bytes
def pad(s: bytes) -> bytes:
    n = 16 - (len(s) & 0xF)
    return s + bytes([n] * n)


# 将填充后的bytes还原
def unpad(s: bytes) -> bytes:
    return s[0 : -s[-1]]


class SM4:
    def __init__(self, key):
        self.set_key(key)

    def set_key(self, key):
        MK = unpack(">4I", key)
        K = array("L", (MK[i] ^ _SM4_FK[i] for i in range(4)))
        K.extend(
            K[i] ^ _T_key(K[i + 1] ^ K[i + 2] ^ K[i + 3] ^ _SM4_CK[i])
            for i in range(32)
        )
        self.e_rk, self.d_rk = K[4:], array("L", reversed(K[4:]))

    def ecb_enc(self, data):
        return array2byte(_ecb_base(self.e_rk, byte2array(data)))

    def ecb_dec(self, data):
        return array2byte(_ecb_base(self.d_rk, byte2array(data)))

    def cbc_enc(self, iv, data):
        return array2byte(_cbc_enc(self.e_rk, byte2array(iv), byte2array(data)))

    def cbc_dec(self, iv, data):
        return array2byte(_cbc_dec(self.d_rk, byte2array(iv), byte2array(data)))


# Crypto - AES-128加密器
# class AES_Cipher:
#     def __init__(self, key):
#         self._key = MD5.new(key).digest()
#         self._ecb = AES.new(self._key, AES.MODE_ECB)

#     # AES加密（ECB模式）
#     def enc(self, data):
#         return self._ecb.encrypt(pad(data))

#     # AES解密（ECB模式）
#     def dec(self, data):
#         assert len(data) & 0xf == 0
#         return unpad(self._ecb.decrypt(data))

#     # AES加密（CBC模式）
#     def enc_cbc(self, iv, data):
#         assert len(iv) == 16
#         return AES.new(self._key, AES.MODE_CBC, iv).encrypt(pad(data))

#     # AES解密（CBC模式）
#     def dec_cbc(self, iv, data):
#         assert len(iv) == 16
#         assert len(data) & 0xf == 0
#         return unpad(AES.new(self._key, AES.MODE_CBC, iv).decrypt(data))

# gmssl - SM4加密器
# class SM4_gmssl:
#     def __init__(self, raw_key):
#         key = raw_key
#         self._enc = CryptSM4()
#         self._enc.set_key(key, SM4_ENCRYPT)
#         self._dec = CryptSM4()
#         self._dec.set_key(key, SM4_DECRYPT)
#
#     # SM4加密（ECB模式）
#     def enc(self, data):
#         return self._enc.crypt_ecb(data)
#
#     # SM4解密（ECB模式）
#     def dec(self, data):
#         assert len(data) & 0xf == 0
#         return self._dec.crypt_ecb(data)
#
#     # SM4加密（CBC模式）
#     def enc_cbc(self, iv, data):
#         assert len(iv) == 16
#         return self._enc.crypt_cbc(iv, data)
#
#     # SM4解密（CBC模式）
#     def dec_cbc(self, iv, data):
#         assert len(iv) == 16
#         assert len(data) & 0xf == 0
#         return self._dec.crypt_cbc(iv, data)


# my - SM4加密器
class MyCryptSM:
    def __init__(self, key):
        self.sm4 = SM4(key)

    # SM4加密（ECB模式）
    def enc(self, data):
        return self.sm4.ecb_enc(pad(data))

    # SM4解密（ECB模式）
    def dec(self, data):
        assert len(data) & 0xF == 0
        return unpad(self.sm4.ecb_dec(data))

    # SM4加密（CBC模式）
    def enc_cbc(self, iv, data):
        assert len(iv) == 16
        return self.sm4.cbc_enc(iv, pad(data))

    # SM4解密（CBC模式）
    def dec_cbc(self, iv, data):
        assert len(iv) == 16
        assert len(data) & 0xF == 0
        return unpad(self.sm4.cbc_dec(iv, data))

    def __init__(self, key_code, public_key, private_key):
        self.key = key_code[0:16].encode()
        self.iv = (key_code[0:8] + key_code[-8:]).encode()
        self.public_key = public_key
        self.private_key = private_key
        self.sm4 = SM4(self.key)

    def sm4_encrypt_cbc_data(self, origin_data, timestamp):
        enc_data = self.enc_cbc(self.iv, json.dumps(origin_data).encode())
        base64_enc_data = base64.b64encode(enc_data)
        sign = sm3.sm3_hash(func.bytes_to_list(base64_enc_data + timestamp.encode()))
        encrypt_data = base64_enc_data.decode() + sign
        return encrypt_data

    def sm4_decrypt_cbc_data(self, encrypt_data):
        base64_decode_str = base64.b64decode(encrypt_data)
        origin_data = self.dec_cbc(self.iv, base64_decode_str)
        return json.loads(origin_data)

    def sm2_encrypt_keycode(self, key_code):
        sm2_crypt = CryptSM2(
            public_key=self.public_key, private_key=self.private_key, mode=1
        )
        kcode = bytes.hex(key_code.encode("utf-8"))
        skey = sm2_crypt.encrypt(kcode.encode("utf-8"))
        # print('skey: ', bytes.hex(skey))
        base64_skey = "04" + binascii.hexlify(skey).decode("utf-8")
        return base64_skey

    def sm3_sign_appkey(self, appkey, timestamp):
        return sm3.sm3_hash(func.bytes_to_list(appkey.encode() + timestamp.encode()))


if __name__ == "__main__":
    keycode = "101230956927207479677402038056359"
    key = keycode[0:16].encode()
    iv = (keycode[0:8] + keycode[-8:]).encode()
    appKey = "3def6c365d284881bf1a9b2b502ee68c"
    appSecret = "ab7357dae64944a197ace37398897f64"
    publicKey = "042BC7AD510BF9793B7744C8854C56A8C95DD1027EE619247A332EC6ED5B279F435A23D62441FE861F4B0C963347ECD5792F380B64CA084BE8BE41151F8B8D19C8"
    privkeyhex = "cb772811f1fef955ce1b4051130870d86cca6afede806f1e7c225d7359591d2b"
    pubkeyhex = "0475e60ab5b94860dad0c2d193551a8b7a628a611df332e23dfcb42f6ecc348653b8a49418e52ff8872b500eeaf8be8c43b7389d115e91b7432bb1c939e764d31a"

    sm4_my = MyCryptSM(key)
    data = sm4_my.enc_cbc(iv, "123456".encode())
    print("my_enc_cbc: ", data)
    base64EncodedStr = base64.b64encode(data)
    print("encode:", base64EncodedStr)
    base64DecodedStr = base64.b64decode(base64EncodedStr)
    print("decoded:", base64DecodedStr)
    data2 = sm4_my.dec_cbc(iv, base64DecodedStr)
    print("ssl_dec_cbc: ", data2)

    sm4_ssl = SM4_gmssl(key)
    data = sm4_ssl.enc_cbc(iv, "123456".encode())
    print("ssl_enc_cbc: ", data)
    data2 = sm4_ssl.dec_cbc(iv, data)
    print("ssl_dec_cbc: ", data2)
