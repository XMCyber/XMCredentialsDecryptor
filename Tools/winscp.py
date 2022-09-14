import sys
import json
try:
    import _winreg as winreg
except ImportError:
    import winreg

class WinSCP():
    # Regedit
    HKEY_CURRENT_USER = -2147483647
    KEY_READ = 131097

    def __init__(self):
        self.hash = ''

    def OpenKey(self, key, path, index=0, access=KEY_READ):
        return winreg.OpenKey(key, path, index, access | winreg.KEY_WOW64_64KEY)

    def decrypt_char(self):
        hex_flag = 0xA3
        charset = '0123456789ABCDEF'

        if len(self.hash) > 0:
            unpack1 = charset.find(self.hash[0])
            unpack1 = unpack1 << 4

            unpack2 = charset.find(self.hash[1])
            result = ~((unpack1 + unpack2) ^ hex_flag) & 0xff

            # store the new hash
            self.hash = self.hash[2:]

            return result

    def check_winscp_installed(self):
        try:
            key = self.OpenKey(self.HKEY_CURRENT_USER, 'Software\\Martin Prikryl\\WinSCP 2\\Configuration\\Security')
            return key
        except Exception as e:
            return False

    def check_masterPassword(self, key):
        is_master_pwd_used = winreg.QueryValueEx(key, 'UseMasterPassword')[0]
        winreg.CloseKey(key)
        if str(is_master_pwd_used) == '0':
            return False
        else:
            return True

    def get_credentials(self):
        try:
            key = self.OpenKey(self.HKEY_CURRENT_USER, 'Software\\Martin Prikryl\\WinSCP 2\\Sessions')
        except Exception as e:
            return False

        pwd_found = []
        num_profiles = winreg.QueryInfoKey(key)[0]
        for n in range(num_profiles):
            name_skey = winreg.EnumKey(key, n)
            skey = self.OpenKey(key, name_skey)
            num = winreg.QueryInfoKey(skey)[1]

            values = {}
            elements = {'HostName': 'URL', 'UserName': 'Login', 'PortNumber': 'Port', 'Password': 'Password'}
            for nn in range(num):
                k = winreg.EnumValue(skey, nn)

                for e in elements:
                    if k[0] == e:
                        if e == 'Password':
                            try:
                                values['Password'] = self.decrypt_password(
                                    username=values.get('Login', ''),
                                    hostname=values.get('URL', ''),
                                    _hash=k[1]
                                )
                            except Exception as e:
                                self.debug(str(e))
                        else:
                            values[elements[k[0]]] = str(k[1])

            if num != 0:
                if 'Port' not in values:
                    values['Port'] = '22'

                pwd_found.append(values)

            winreg.CloseKey(skey)
        winreg.CloseKey(key)

        return pwd_found

    def decrypt_password(self, username, hostname, _hash):
        self.hash = _hash
        hex_flag = 0xFF

        flag = self.decrypt_char()
        if flag == hex_flag:
            self.decrypt_char()
            length = self.decrypt_char()
        else:
            length = flag

        ldel = (self.decrypt_char()) * 2
        self.hash = self.hash[ldel: len(self.hash)]

        result = ''
        for ss in range(length):

            try:
                result += chr(int(self.decrypt_char()))
            except Exception as e:
                return False

        if flag == hex_flag:
            key = username + hostname
            result = result[len(key): len(result)]

        return result

    def run(self):
        print("----Running WinSCP Password Decryptor----")
        winscp_key = self.check_winscp_installed()
        if winscp_key:
            if not self.check_masterPassword(winscp_key):
                results = self.get_credentials()
                if results:
                    print(json.dumps(results, indent=4, sort_keys=True))
                    return results
            else:
                print("WinSCP Error")

