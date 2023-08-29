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
import time
import traceback
from tabulate import tabulate
import eel
from random import randint

_verbose = False
_dbfile = None


def play(msg):
    if msg is None or msg == '':
        return
    myobj = gTTS(text=msg, lang='en', tld='com.au', slow=False)
    myobj.save('/tmp/bee.mp3')
    p = vlc.MediaPlayer('/tmp/bee.mp3')
    p.play()


def init():
    global _verbose
    init_dir = Path.home().joinpath(".bee")
    if init_dir.is_dir():
        return True
    else:
        try:
            os.mkdir(init_dir)
        except OSError as error:
            if _verbose:
                print(error)
            return False
        return True


def init_db():
    global _verbose
    global _dbfile
    home_dir = Path.home()
    db_file = Path.home().joinpath('.bee').joinpath('bee.db')
    conn = None
    try:
        conn = sqlite3.connect(db_file)
        if conn:
            # for now keep the schema simple
            cursor = conn.execute('''CREATE TABLE IF NOT EXISTS bee (bee_id
                                  INTEGER PRIMARY KEY, bee_name TEXT, salt TEXT, 
                                  encrypted_words TEXT)''')
            _dbfile = db_file
    except sqlite3.Error as error:
        if _verbose:
            errs = (' '.join(error.args))
            print(errs)
            print('Traceback:')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))
        return False
    finally:
        if conn:
            conn.close()
    return True


def add_bee(bee_name, password, bee_words):
    global _verbose
    global _dbfile
    conn = None
    try:
        conn = sqlite3.connect(_dbfile)
        if conn:
            # for now keep the schema simple
            cursor = conn.cursor()
            bee_crypt, salt = encrypt(bee_words, password)
            salt_b64 = base64.urlsafe_b64encode(salt)
            cursor.execute(
                'INSERT INTO bee(bee_name, salt, encrypted_words) VALUES (?, ?, ?)',
                (bee_name, salt_b64, bee_crypt))
            conn.commit()
    except sqlite3.Error as error:
        if _verbose:
            errs = (' '.join(error.args))
            print(f'Error adding bee: {errs}')
            print('Traceback:')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))
        return False
    finally:
        if conn:
            conn.close()
    return True


@eel.expose
def list_bees():
    global _verbose
    global _dbfile
    conn = None
    rows = []
    try:
        conn = sqlite3.connect(_dbfile)
        if conn:
            # for now keep the schema simple
            cursor = conn.cursor()
            rows = cursor.execute('SELECT bee_name FROM bee').fetchall()
            return rows
    except sqlite3.Error as error:
        if _verbose:
            errs = (' '.join(error.args))
            print(f'Error listing bees: {errs}')
            print('Traceback:')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))
        return rows
    finally:
        if conn:
            conn.close()
    return rows


def get_bee(bee_name):
    global _verbose
    global _dbfile
    conn = None
    bees = []
    try:
        conn = sqlite3.connect(_dbfile)
        if conn:
            # for now keep the schema simple
            cursor = conn.cursor()
            rows = cursor.execute(
                "SELECT salt, encrypted_words FROM bee WHERE bee_name = ?",
                (bee_name, )).fetchall()
            if len(rows) == 0:
                return None, None
            else:
                return rows[0][0], rows[0][1]
    except sqlite3.Error as error:
        if _verbose:
            errs = (' '.join(error.args))
            print(f'Error in add_bee: {errs}')
            print('Traceback:')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))
        return None, None
    finally:
        if conn:
            conn.close()
    return None, None


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
    return bee_crypt, salt


def decrypt(cipher_text, salt, password):
    passwd = bytes(password, 'utf-8')
    # TODO convert salt into bytes base64 decode
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),
                     length=32,
                     salt=salt,
                     iterations=480000)
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    f = Fernet(key)
    plain_text = f.decrypt(cipher_text)
    return plain_text


def fetch_bee(bee_name, password):
    salt_b64, bee_crypt = get_bee(bee_name)
    salt = base64.urlsafe_b64decode(salt_b64)
    bee = decrypt(bee_crypt, salt, password)
    return bee


def play_bee(bee_name, password, interval):
    bee = fetch_bee(bee_name, password)
    bee_str = bytes.decode(bee, 'utf-8')
    lines = bee_str.split('\n')
    for line in lines:
        play(line)
        time.sleep(int(interval))


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Spelling bee tool for kids')
    parser.add_argument('-w',
                        '--wordlist',
                        type=str,
                        action='store',
                        help='Path to the wordlist text file.')
    parser.add_argument('-a',
                        '--add',
                        action='store_true',
                        help='Add wordlist to spelling bee database')
    parser.add_argument('-p',
                        '--password',
                        type=str,
                        action='store',
                        help='data store password')
    parser.add_argument(
        '-n',
        '--name',
        action='store',
        help='Unique spelling bee name. Example: Grade 5 Level 1')
    parser.add_argument('-l',
                        '--list',
                        action='store_true',
                        help='List available bees')
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Verbose mode prints additional information and/or internal errors'
    )
    parser.add_argument('-s',
                        '--start',
                        action='store_true',
                        help='Start a bee')
    parser.add_argument('-i',
                        '--interval',
                        action='store',
                        help='Time interval (in seconds) between words')
    parser.add_argument('-g', '--gui', action='store_true', help='Start GUI')

    args = parser.parse_args()

    if args.verbose:
        _verbose = args.verbose

    ok = init()
    if not ok:
        print(
            'Initialization error. Re-run with --verbose for a detailed error message'
        )
        exit(1)

    ok = init_db()
    if not ok:
        print(
            'Database initialization error. Re-run with --verbose for a detailed error message'
        )
        exit(1)

    if args.add:
        if args.wordlist and args.password and args.name:
            with open(args.wordlist, 'r') as fp:
                data = fp.read()
                add_bee(args.name, args.password, data)
        else:
            print('Adding bee requires wordlist, password and a bee name')
            print()
            parser.print_help()
            sys.exit(0)
    elif args.list:
        v = list_bees()
        if v is False:
            print(
                'Error listing bees. Re-run with --verbose to view detailed errors'
            )
    elif args.start:
        if args.password and args.name and args.interval:
            if args.interval.isdigit():
                play_bee(args.name, args.password, args.interval)
            else:
                print('Interval needs to be an integer')
                print()
                parser.print_help()
                exit(1)
        else:
            print(
                'To start a bee the bee name, interval and password are required'
            )
            print()
            parser.print_help()
            exit(1)
    elif args.gui:
        eel.init("web")
        eel.start("index.html")
    else:
        parser.print_help()
        sys.exit(0)
