from random import random
from io import TextIOWrapper
from hashlib import sha256, md5
from os import remove as os_remove

class NonCipherError(BaseException): pass
class HashNotSettedError(NonCipherError): pass
class KeysNotSettedError(NonCipherError): pass
class InvalidHashingAlgorithm(NonCipherError): pass

TRY_TO_DECRYPT = '~\tW\x17\x14|\x0b\x11L^\x12d\n\x04\x04\x15\x01\x15\x16D@\x0b\x15\x04\x18\\QFE\x1e^\\KV\nFk\x11\x15RB^^RYFYP\x06TQW\x0c\x06\x03WR\x0fV\x01W\x07\x06\x05\x06\x02QU\x01R\x08\x06\x07ZQT\\RY\r\x08SV\x00US\rP\x02Q\x06\x04\x08\x08W\n\x02\x00RQ\x07\x07TV\nQ\x03\x06S\x03'
# |                                                              |
# v                                                              |                 
# PEP 8, Sorry :'(                                               |
# First letter is 'O', last is '6'. String is readable. Good luck!

class NonOpen(TextIOWrapper):
    '''Like a standart TextIOWrapper but after read removes file'''
    def read(self,remove_temp=True):
        '''      
        kwarg remove_temp -- if True - remove file after read
            |                      |
            (type must be int(bool))
        '''        
        string = open(self.name,self._read_mode).read()   
        if remove_temp: os_remove(self.name)
        return string
        

class NonTempFile:
    '''
    This class is needed to create a file, 
    and then write to it the encrypted/decrypted symbols. 
    It can be useful when you encrypt a file that is too large,  
    in which case the program will keep everything 
    on your disk, and not RAM.
    '''
    def __init__(self,string_type='str',filename=None):
        '''
        kwarg string_type -- type of string{symbols} 
        |   which you want to write in file. 
        |   must be string_type='str' or string_type='bytes'
        |   by default == 'str'
        |                |
        (type must be str)
        
        kwarg filename -- name of temporary file
            if not specified{None} - filename be random digits
            |                |
            (type must be str)
        
        '''
        self._write_type = 'wb' if string_type == 'bytes' else 'w'
        self._read_type = 'rb' if self._write_type == 'wb' else 'rt'        
        self._temp_file_name = str(random())[2:] + '.nc_temp' if not filename else filename
        self._temp_file = open(self._temp_file_name,self._write_type)
    
    def __iadd__(self,other):
        self._temp_file.write(other)
        return self
    
    def close(self):
        '''analogue of opened_file.close()'''
        self._temp_file.close()
    

class NonCipher:
    '''
    Main NonCipher class.
    '''
    def __init__(self,password,secret_word,iterations):
        '''
        arg password -- your password
            |                  |
            (type must be str or bytes)

        arg salt -- your secret_word{or salt} for hashing
            |                  |
            (type must be str or bytes)

        arg iterations -- iterations count.
            Note that the larger the number, the longer it takes to
            generate the input key.  Do not put the number > 200,000
            if you do not want to wait, if you are want to get better
            crypto-resistance - put more than 200,000
                |                |
                (type must be int)                
        '''
        self._password = password if isinstance(password,bytes) else password.encode()
        self._secret_word = secret_word if isinstance(secret_word,bytes) else secret_word.encode()
        self._iterations = iterations if iterations > 0 else 1
        self._password_hash = None
        self._keys_for_cipher = None
        self._hash_of_nc_setup = None

    @staticmethod
    def get_hash_of(password,salt,iterations,algorithm='sha256'):
        '''
        function for getting SafePassword{Input key in NonCipher}

        arg password -- password for hashing
            |                  |
            (type must be bytes)

        arg salt -- secret_word{or salt} for hashing
            |                  |
            (type must be bytes)

        arg iterations -- iterations count.
            Note that the larger the number, the longer it takes to
            generate the input key.  Do not put the number > 200,000
            if you do not want to wait, if you are want to get better
            crypto-resistance - put more than 200,000
                |                |
                (type must be int)

        kwarg algorithm -- hashing algorithm.
            For SafePassword default is MD5 but for NonCipher
            it's SHA256. Other alorithms will be threw an error
                |                |
                (type must be str)

        '''
        if algorithm == 'sha256':
            hash_a = sha256
        elif algorithm == 'md5':
            hash_a = md5
        else:
            raise InvalidHashingAlgorithm('Avaliable only md5 and sha256')

        for i in range(iterations):
            password = hash_a(password + salt).digest()
        return hash_a(password).hexdigest()


    def __get_keys_for_cipher(self,hash=None):
        '''
        private function to get 64 starting hashes(by SHA256 algorithm).
            Used as a password. If the text is longer than 4096 characters,
            new ones will be generated from the last existing hash

        kwarg hash -- If specified, sets and returns a new batch of 64
            hashes from the transferred. If the hash is not setted - throws
            HashNotSettedError{this happens only when the class has not been
            initialized, in other cases the hash is always indicated}
                |                                     |
                (type must be bytes{encoded last hash})
        '''
        if not hash:
            hash = self._password_hash
        if not self._password_hash:
            raise HashNotSettedError(
                'For first you have to set hash via non_cipher_object.init()')
        else:
            decoded_hash = hash.decode()
            self._keys_for_cipher = [
                self.get_hash_of(
                    hash, self._hash_of_nc_setup, ord(i)
                )
                for i in decoded_hash
            ]
            return self._keys_for_cipher


    def init(self):
        '''
        function to initialize and reset the
            keys_for_cipher to the first batch of hashes.

            If you want to decrypt a string with the same class
            object that you encrypted, you need to call the init
            function again, otherwise the class will have the last
            generated hashes(this can be useful for encrypting text in.parts)
            |                                                         |
            This is only necessary if the string you are              |
            encrypting is more than 4096 characters.                  |
            Otherwise, calling this function again does not make sense.

            for example:
                from NonCipher import NonCipher
                from random import choice
                from string import ascii_lowercase as a_l

                for_example = 'Hello, World!' + ''.join(
                    [choice(a_l) for _ in range(10000)])

                nc = NonCipher('NonSense','VerySecretOk?',22)
                nc.init()

                encrypted_string = nc.cipher(for_example)
                decrypted_string = nc.cipher(encrypted_string)
                ^
                |
                # must be var for_example but random symbols

                Correct usage is
                ...
                ...
                encrypted_string = nc.cipher(for_example)
                nc.init()
                decrypted_string = nc.cipher(encrypted_string)
                ^
                |
                # Hello, World!.......
        '''
        self._password_hash = self.get_hash_of(self._password,
            self._secret_word,self._iterations).encode()
        for_hashing = (
            self._password
            + self._secret_word
            + str(self._iterations).encode() 
            + self._password_hash
        )
        self._hash_of_nc_setup = sha256(for_hashing).hexdigest().encode()
        self.__get_keys_for_cipher()


    def cipher(self,string,write_temp=False):
        '''
        function for encrypting and decrypting strings

        arg string -- string for encrypting
            |                         |
            (type must be str or bytes)
        
        kwarg write_temp -- If True, writes the encrypted/decrypted 
        symbols to the file, instead of writing to the RAM.  
        After encryption, a two-element tuple returns — (file_name, file-like object)
        
             
        '''
        if not self._keys_for_cipher:
            raise KeysNotSettedError(
                'For first you have to set keys via non_cipher_object.init()')
        else:
            password = ''.join(self._keys_for_cipher)
            try:
                index = 0
                if write_temp:
                    if isinstance(string,bytes):
                        total_string = NonTempFile(string_type='bytes')
                    else:
                        total_string = NonTempFile()
                else:                        
                    total_string = b'' if isinstance(string,bytes) else ''
                    
                for all in string:
                    if len(password) == index:
                        self.__get_keys_for_cipher(self._keys_for_cipher[-1].encode())
                        password = ''.join(self._keys_for_cipher)
                        index = 0
                        
                    if not isinstance(string,bytes):
                        total_string += chr(ord(all) ^ ord(password[index]))
                    else:
                        total_string += bytes([all ^ ord(password[index])])
                        
                    index += 1
                    
                if write_temp:
                    ts = total_string
                    ts.close()
                    text_io_wrapper = open(ts._temp_file_name,ts._read_type)
                    non_open = NonOpen(text_io_wrapper)
                    non_open._read_mode = ts._read_type
                    return (ts._temp_file_name, non_open)
                else:
                    return total_string
                    
            except Exception as e:
                raise NonCipherError(
                    '''Error in NonCipher! '''
                    f'''Can\'t Encrypt | Decrypt string | {e,type(e)}'''
                )

if __name__ == '__main__':
    string = 'Hello, World!'

    nc_correct = NonCipher('password','secret_word',1000)
    nc_correct.init()
    encrypted_string = nc_correct.cipher(string)

    nc_invalid = NonCipher('password','secret_word',1001)
    nc_invalid.init()
    bad_decrypted_string = nc_invalid.cipher(encrypted_string)

    print([bad_decrypted_string])
