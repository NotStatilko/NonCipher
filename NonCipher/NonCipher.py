from hashlib import sha256, md5

class NonCipherError(BaseException): pass
class HashNotSettedError(NonCipherError): pass
class KeysNotSettedError(NonCipherError): pass
class XorCipherError(NonCipherError): pass
class InvalidHashingAlgorithm(NonCipherError): pass

class NonCipher:
    def __init__(self,password,secret_word,iterations):
        self._password = password if isinstance(password,bytes) else password.encode()
        self._secret_word = secret_word if isinstance(secret_word,bytes) else secret_word.encode()
        self._iterations = iterations if iterations > 0 else 1
        self._password_hash = None
        self._keys_for_cipher = None

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

        arg iterations: iterations count.
            Note that the larger the number, the longer it takes to
            generate the input key.  Do not put the number > 200,000
            if you do not want to wait, if you are want to get better
            crypto-resistance - put more than 200,000
            |                |
            (type must be int)

        kwarg algorithm: hashing algorithm.
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
                    hash, self._secret_word + self._password + \
                    str(self._iterations).encode() + self._password_hash, ord(i)
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
            generated hashes(this can be useful for encoding text in parts)
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
                |
                # must be var for_example but random symbols

                Correct usage is
                ...
                ...
                encrypted_string = nc.cipher(for_example)
                nc.init()
                decrypted_string = nc.cipher(encrypted_string)
                |
                # Hello, World!.......
        '''
        self._password_hash = self.get_hash_of(self._password,
            self._secret_word,self._iterations).encode()
        self.__get_keys_for_cipher()


    def cipher(self,string):
        '''
        function for encrypting and decrypting strings

        arg string: string for encrypting
            |                         |
            (type must be str or bytes)
            
        '''
        if not self._keys_for_cipher:
            raise KeysNotSettedError(
                'For first you have to set keys via non_cipher_object.init()')
        else:
            password = ''.join(self._keys_for_cipher)
            try:
                index = 0
                total_string = b'' if isinstance(string,bytes) else ''
                for all in string:
                    if len(password) == index:
                        self.__get_keys_for_cipher(self._keys_for_cipher[-1].encode())
                        password = ''.join(self._keys_for_cipher)
                        index = 0
                    if not isinstance(total_string,bytes):
                        total_string += chr(ord(all) ^ ord(password[index]))
                    else:
                        total_string += hex(all ^ ord(password[index])).encode()
                    index += 1
                return total_string
            except Exception as e:
                raise XorCipherError(
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
