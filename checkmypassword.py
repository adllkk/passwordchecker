import requests
import hashlib
import sys

def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/'+ query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise  RuntimeError(f'Error fetching:{res.status_code}, check the api and try again')
    return res
def get_password_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h , count in hashes :
        if h == hash_to_check:
            return count
    return 0
    

def pwnd_api_ckeck(password):
    hashpasswor1 = hashlib.sha1(password.encode('UTF-8')).hexdigest().upper()
    first5char , tail = hashpasswor1[:5] , hashpasswor1[5:]
    response = request_api_data(first5char)
    return get_password_count(response, tail)


def main(args):
    for password in args:
        count = pwnd_api_ckeck(password)
        if count:
            print(f'{password} was found {count} times... you should think about something else')
        else:
            print(f'this {password} was not found, all good')
    return 'we done to check!'
if __name__=='__main__':
    sys.exit(main(sys.argv[1:]))


