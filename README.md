## Spelling Bee

![Bee](https://github.com/opcoder0/bee/blob/main/web/images/bee.png)

Bee is a spelling bee software written in Python. The application that enables creators create spelling bee tests for kids using words of their choice. The application uses the user's home directory (`$HOME/.bee`) as the data directory to store the wordlist in a SQLite3 database (`bee.db`). The wordlist is encrypted using a password provided during the creation of a bee.


## Usage

```
usage: bee.py [-h] [-w WORDLIST] [-a] [-p PASSWORD] [-n NAME] [-l] [-v] [-s] [-i INTERVAL]

Spelling bee tool for kids

optional arguments:
  -h, --help            show this help message and exit
  -w WORDLIST, --wordlist WORDLIST
                        Path to the wordlist text file.
  -a, --add             Add wordlist to spelling bee database
  -p PASSWORD, --password PASSWORD
                        data store password
  -n NAME, --name NAME  Unique spelling bee name. Example: Grade 5 Level 1
  -l, --list            List available bees
  -v, --verbose         Verbose mode prints additional information and/or internal errors
  -s, --start           Start a bee
  -i INTERVAL, --interval INTERVAL
                        Time interval (in seconds) between words
```

### To create a bee

```
python bee.py -a -w $PWD/example_wordlist.txt -n 'Grade 5 Level 1' -p 'mypa$$w0 rd'
```

This is going to encrypt the wordlist with a salt and store it into the bee database.

### To view all the available bees 

```
python bee.py -l
```

This is going to display all the bees that have been added to the bee database.

### To start a bee

```
python bee.py -n 'Grade 5 Level 1' -p 'mypa$$w0 rd' -s -i 20
```

This is going to start the spelling bee by reading off the word list with a gap of 20 seconds between the words. Be sure to have your speakers unmuted.
