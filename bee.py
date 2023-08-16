from gtts import gTTS
import vlc
import argparse
import sys
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from pathlib import Path
import sqlite3

# def play(filename, key):
#     language = 'en'
#     f = open(filename, 'r')
#     lines = f.readlines()
#     for line in lines:
#         myobj = gTTS(text=line, lang=language, tld='com.au', slow=False)
#         myobj.save("word.mp3")
#         p = vlc.MediaPlayer("word.mp3")
#         p.play()
#         time.sleep(1.0)
#         duration = p.get_length() / 1000
#         time.sleep(duration)
#         p.stop()
#


def init():
    home_dir = Path.home()
    init_dir = os.path.join(home_dir, ".bee")
    is_dir = os.path.isdir(init_dir)
    if is_dir is True:
        return
    else:
        try:
            os.mkdir(init_dir)
        except OSError as error:
            print('Initialization failed:', error)
            sys.exit(1)


def create_db():
    home_dir = Path.home()
    init_dir = os.path.join(home_dir, ".bee")
    db_file = os.path.join(init_dir, 'bee.db')
    conn = None
    try:
        conn = sqlite3.connect(db_file)
    except Error as error:
        print('Error creating database', error)
    finally:
        if conn:
            conn.close()


def encrypt(source, password):
    passwd = bytes(password, 'utf-8')
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    f = Fernet(key)
    bee_crypt = f.encrypt(bytes(source, 'utf-8'))
    return bee_crypt


if __name__ == '__main__':

    init()
    # create_db()

    parser = argparse.ArgumentParser(description="Spelling bee tool for kids")
    parser.add_argument("-a",
                        "--add",
                        metavar='/path/to/source/file',
                        type=str,
                        action='store',
                        help="create spelling bee data store")
    parser.add_argument("-p",
                        "--password",
                        type=str,
                        action='store',
                        help="data store password")
    parser.add_argument("-")

    args = parser.parse_args()
    if args.add:
        print('Adding spelling bee source:', args.add, 'to the bee database')
        with open(args.create, 'r') as f:
            data = f.read()
            bee_crypt = encrypt(data, args.password)
            print(bee_crypt)
    elif (args.create and not args.password) or (args.password
                                                 and not args.create):
        print(
            'Arguments create and password are required to create a data store.'
        )
        sys.exit(1)
    else:
        parser.print_help()
        sys.exit(0)
