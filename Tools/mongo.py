from Tools.simplecrypt import SimpleCrypt
import json
import os
from os import path

class Robomongo():

    def __init__(self):

        self.paths = [
            {
                'directory': u'.3T/robo-3t/1.4.4',
                'filename': u'robo3t.json',
            }
        ]

    def read_file_content(self, file_path):
        """
        Read the content of a file
        :param file_path: Path of the file to read.
        :return: File content as string.
        """
        content = ""
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file_handle:
                content = file_handle.read()
        return content

    def parse_json(self, connection_file_path, key_file_path):
        repos_creds = []
        if not os.path.exists(connection_file_path):
            return repos_creds
        with open(key_file_path) as key_file:
            try:
                key = self.read_file_content(key_file_path)
                crypto = SimpleCrypt(int(key))
            except Exception:
               return repos_creds
        with open(connection_file_path) as connection_file:
            try:
                connections_infos = json.load(connection_file)
            except Exception:
                return repos_creds
            for connection in connections_infos.get("connections", []):
                try:
                    creds = {
                        "Name": connection["connectionName"],
                        "Host": connection["serverHost"],
                        "Port": connection["serverPort"]
                    }
                    crd = connection["credentials"][0]
                    if crd.get("enabled"):
                        creds.update({
                            "AuthMode": "CREDENTIALS",
                            "DatabaseName": crd["databaseName"],
                            "AuthMechanism": crd["mechanism"],
                            "Login": crd["userName"],
                            "Password": crypto.decrypt_to_string(crd["userPasswordEncrypted"])
                        })
                    else:
                        creds.update({
                            "Host": connection["ssh"]["host"],
                            "Port": connection["ssh"]["port"],
                            "Login": connection["ssh"]["userName"]
                        })
                        if connection["ssh"]["enabled"] and connection["ssh"]["method"] == "password":
                            creds.update({
                                "AuthMode": "SSH_CREDENTIALS",
                                "Password": crypto.decrypt_to_string(connection["ssh"]["userPasswordEncrypted"])
                            })
                        else:
                            creds.update({
                                "AuthMode": "SSH_PRIVATE_KEY",
                                "Passphrase": connection["ssh"]["passphrase"],
                                "PrivateKey": self.read_file_content(connection["ssh"]["privateKeyFile"]),
                                "PublicKey": self.read_file_content(connection["ssh"]["publicKeyFile"])
                            })
                    repos_creds.append(creds)
                except Exception as e:
                    print(u"Cannot retrieve connections credentials '{error}'".format(error=e))

        return repos_creds

    def run(self):
        """
        Extract all connection's credentials.
        :return: List of dict in which one dict contains all information for a connection.
        """
        print("----Running RoboMongo Password Decryptor----")
        pwd_found = []
        for directory in self.paths:
            connection_file_path = os.path.join(path.expandvars(r"%USERPROFILE%"),
                                                directory['directory'],
                                                directory['filename'])
            key_file_path = os.path.join(path.expandvars(r"%USERPROFILE%"),
                                                directory['directory'],
                                                u'../robo3t.key')
            pwd_found.extend(self.parse_json(connection_file_path, key_file_path))
        if not pwd_found:
            return False
        print(json.dumps(pwd_found, indent=4, sort_keys=True))
        return pwd_found
