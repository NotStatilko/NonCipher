import os
from secrets import token_hex
from types import GeneratorType
from hashlib import sha256, sha512, md5
from multiprocessing import Process, Queue
from io import TextIOWrapper, BufferedReader

class NonCipherError(BaseException): pass
class HashNotSettedError(NonCipherError): pass
class KeysNotSettedError(NonCipherError): pass
class InvalidHashingAlgorithm(NonCipherError): pass
class InvalidConfigurationError(NonCipherError): pass
class TextTooSmallError(NonCipherError): pass

__version__ = '4.0'

TRY_TO_DECRYPT = ('''y^V\x19D|X\x11\x19^\x17iXR\x05AT\x19E\x16FZAW'''
    '''\x12\x0bS\x15\x10HT\x07JX\\\x16:JARBP\rR^F\x01'''
    '''\x05\x00TV\x07\x05PSP\r\x02W\x04\x05\x01\x04\x04'''
    '''\x04\x01\x02WT\x03\x02\x08\x0f[\x00\x07]R\x00'''
    '''ZUQUV\x01\x00\x02\r[\x04QR\nSQ\t\x0f\x0fU\x04Q\nUW\tUQUPU''')

def get_hash_of(password,salt,iterations,algorithm='sha256'):
    '''
    function for getting SafePassword{Primary hash in NonCipher}

    arg password -- password for hashing
        (type must be str | bytes)

    arg salt -- secret_word{or salt} for hashing
        (type must be str | bytes)

    arg iterations -- iterations count.
        Note that the larger the number, the longer it takes to
        generate the primary hash.  Do not put the number > 5,000,000
        if you do not want to wait, if you are want to get better
        crypto-resistance - put more than 5,000,000
            (type must be int)

    kwarg algorithm -- hashing algorithm.
        For SafePassword(bit.ly/SafePassword) default is MD5 but for NonCipher
        it's SHA256 and SHA512. Other alorithms will be threw an error
            (type must be str)

    '''
    hashing_algorithms = {'md5': md5, 'sha256': sha256, 'sha512': sha512}
    if algorithm.lower() in hashing_algorithms:
        hashing_algorithm = hashing_algorithms[algorithm]
    else:
        raise InvalidHashingAlgorithm('Avaliable only MD5, SHA256 and SHA512')

    if isinstance(password,str):
        password = password.encode()

    if isinstance(salt,str):
        salt = salt.encode()

    for i in range(iterations):
        password = hashing_algorithm(password + salt).digest()
    return hashing_algorithm(password).hexdigest()

class FileByParts:
    '''Class for reading files by parts'''
    def __init__(self,filename,mode,part_size=1):
        '''
        arg filename -- name of file with extension.
            For example picture.png
                (type must be str)

        arg read_mode -- Read mode for file.
            For example 'rt' or 'rb'
                (type must be str)

        kwarg part_size -- The size of the part of the file
            returned for each iteration
                (type must be int)
        '''
        self.mode = mode
        self.opened_file = open(filename,mode)
        self.part_size = part_size

    def __iter__(self):
        return self

    def __next__(self):
        next_part = self.opened_file.read(self.part_size)
        if next_part:
            return next_part
        else:
            raise StopIteration

    def __str__(self):
        return self.opened_file.name

    def remove(self):
        if not self.opened_file.closed:
            self.opened_file.close()
        os.remove(self.opened_file.name)

    def close(self):
        self.opened_file.close()

class NonOpen(TextIOWrapper):
    '''Like a standart TextIOWrapper but after read removes file'''
    def __init__(self,file_like_object):
        super().__init__(file_like_object)
        self.flo = file_like_object

    def read(self,remove_temp=True):
        '''
        kwarg remove_temp -- if True - removes file after read
            (type must be int(bool))
        '''
        string = self.flo.read()
        self.flo.close()
        if remove_temp:
            os.remove(self.flo.name)
        return string

class NonTempFile:
    '''
    This class is needed to create a file
    and write to it the encrypted/decrypted symbols.
    It can be useful when you encrypt a file that is too large,
    in which case the program will keep everything
    on your disk, and not RAM.
    '''
    def __init__(self,string_type='str',filename=None):
        '''
        kwarg string_type -- type of string{symbols} which you want to write in file.
            must be string_type='str' or string_type='bytes' by default == 'str'
                (type must be str)

        kwarg filename -- name of temporary file with extension
            if not specified{None} - filename be random symbols
                (type must be str)
        '''
        self._write_type = 'wb' if string_type == 'bytes' else 'w'
        self._read_type = 'rb' if self._write_type == 'wb' else 'rt'
        self._temp_filename = 'nontempfile_' + token_hex(4) + '.nc_temp' if not filename else filename
        self._opened_temp_file = open(self._temp_filename, self._write_type)

    def __iadd__(self,other):
        self._opened_temp_file.write(other)
        return self

    @property
    def filename(self):
        return self._temp_filename

    def close(self):
        '''analogue of open(/).close()'''
        if self._opened_temp_file:
            self._opened_temp_file.close()


class NonCipher:
    '''
    Main NonCipher class.

    GitHub repository: github.com/NotStatilko/NonCipher

    Note: To implement multi(processing/threading),
    all args are now kwargs, but you have
    to choose one thing: either set a
    password, a secret word, and the number of iterations,
    or primary_hash and hash_of_input_data.

    {Example} NonCipher with multiprocessing

        from NonCipher import NonCipher
        from multiprocessing import Process

        nc = NonCipher('password','secret_word',1)
        nc.init()

        def nc_process_test(ph,hoid):
            nc = NonCipher(
                primary_hash=ph,
                hash_of_input_data=hoid
            )
            nc.init()

            with open('picture.jpg','rb') as f:
                print(nc.cipher(f,write_temp=True))

        if __name__ == '__main__':
            for i in range(5):
                args = (nc._primary_hash,nc._hash_of_input_data)
                Process(target=nc_process_test,args=args).start()
    '''
    def __init__(self,password=None,secret_word=None,iterations=None,primary_hash=None,hash_of_input_data=None):
        '''
        kwarg password -- your password
            (type must be str | bytes)

        kwarg secret_word -- your secret_word{salt} for hashing
            (type must be str | bytes)

        kwarg iterations -- iterations count.
            Note that the larger the number, the longer it takes to
            generate the primary hash. Do not put the number > 5,000,000
            if you don't want to wait, if you are want to get better
            crypto-resistance - put more than 5,000,000
                (type must be int)

        kwarg primary_hash -- hash from your input data from past NonCipher obj
            you can get it with non_cipher_object._primary_hash
                (type must be bytes)

        kwarg hash_of_input_data -- hash of input data from your past NonCipher obj
            you can get it with non_cipher_object._hash_of_input_data
                (type must be bytes)
        '''
        self.cipher_process_count = 10
        self.__cipher_process_part_number = None
        if all((password,secret_word,iterations)):
            self._password = password if isinstance(password,bytes) else password.encode()
            self._secret_word = secret_word if isinstance(secret_word,bytes) else secret_word.encode()
            self._iterations = iterations if iterations > 0 else 1
            self._primary_hash = None
            self._hash_of_input_data = None
            self._block = None

        elif all((primary_hash,hash_of_input_data)):
            self._password = None
            self._primary_hash = primary_hash
            self._hash_of_input_data = hash_of_input_data
        else:
            raise InvalidConfigurationError('Please run help(NonCipher)')

    def __get_hash_blocks(self,hash,blocks_count=1):
        '''
        private function for getting blocks of hashes
            This feature came to replace the old self.__get_keys_for_cipher

        arg hash -- The hash from which the
            block of other hashes will be created.
                (type must be bytes{encoded hash})

        kwarg blocks_count -- The number of blocks to create. 1 by default.
            The first block will be created from the transferred hash,
            the subsequent ones from the last hash in the last block.
            If blocks_count > 1{default} Blocks will be merged into one password.
            This password will be written to a file to speed up the work of NonCipher,
            after encryption it will be deleted. Please note that this file is
            a password to your file, so it can not be distributed to anyone.
                (type must be int)
        '''
        if isinstance(blocks_count, float):
            blocks_count = int(blocks_count) + 1

        if not hash:
            raise HashNotSettedError('For first you have to set hash via non_cipher_object.init()')
        else:
            if blocks_count == 1:
                hash_block = []
            else:
                hash_block = NonTempFile(
                    filename='password_block_' + token_hex(4), string_type='bytes'
                )
            for _ in range(blocks_count):
                unique_numbers = set([
                    *sha256(self._primary_hash + hash).digest(),
                    *sha256(self._hash_of_input_data + hash).digest(),
                    *sha256(self._primary_hash + self._hash_of_input_data + hash).digest()
                ])
                part_block = [
                    sha256(hash + self._hash_of_input_data + str(i).encode()).hexdigest()
                    for i in list(unique_numbers)[:64]
                ]
                hash = part_block[-1].encode()
                hash_block += part_block if blocks_count == 1 else ''.join(part_block).encode()

            if isinstance(hash_block,NonTempFile):
                hash_block.close()
                return open(hash_block.filename,'rb')
            else: return hash_block

    def init(self):
        '''
        function to initialize and reset self._block
            to the primary block.

            If you want to decrypt a string with the same class
            object that you encrypted, you need to call the init
            function again, otherwise the class will have the last
            generated hashes(this can be useful for encrypting text in parts)

            This is only necessary if the string you are
            encrypting is more than 4096 characters.
            Otherwise, calling this function again does not make sense

            for example:
                from NonCipher import NonCipher
                from random import choice
                from string import ascii_lowercase as a_l

                for_example = 'Hello, World!' + ''.join(
                    [choice(a_l) for _ in range(10000)]
                )
                nc = NonCipher('NonSense','VerySecretOk?',22)
                nc.init()

                encrypted_string = nc.cipher(for_example)
                decrypted_string = nc.cipher(encrypted_string)
                ^
                |
                # must be var for_example but "random" symbols

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
        if self._password:
            self._primary_hash = sha512(get_hash_of(self._password,
                self._secret_word,self._iterations).encode()).hexdigest().encode()

            for_hashing = (
                self._password
                + self._secret_word
                + str(self._iterations).encode()
                + self._primary_hash
            )
            self._hash_of_input_data = sha256(for_hashing).hexdigest().encode()
            self._hash_of_input_data = sha512(self._hash_of_input_data).hexdigest().encode()

        self._block = self.__get_hash_blocks(self._primary_hash)

    def cipher(self,what,write_temp=False,run_in_processes=False,queue=None,cipher_process_count_for_now=None):
        '''
        function for encrypting and decrypting encrypted by NonCipher strings.

        arg what -- string, generator, or file-like
            object(readable) for encrypting
                (type must be str | bytes | file-like-object | GeneratorType)

        kwarg write_temp -- If True, writes the encrypted/decrypted
            symbols to the file, instead of writing to the RAM.
            Returns a two-element tuple - (file_name.ncfile, file-like object)
               (type must be int(bool))

        kwarg run_in_processes -- If True, NonCipher divides
            the encrypted data by self.cipher_process_count{10 by default},
            and encrypts it in different processes.
            Each process will write to the file, so
            there is no point in specifying a write_temp.
            Due to this, the speed increases by many times.
            Be careful if you have a slow computer.
                (type must be int(bool))

        kwarg queue -- If specified, put the encrypted data in the queue.
            If write_temp is True, a two-element tuple inserts into the Queue,
            the second element of which will be the file name.
                (must be any Queue class. For example queue.Queue)

        kwarg cipher_process_count_for_now -- if specified, encrypts in parts
            in processes without use and changing self.cipher_process_count.
                (type must be int)
        '''
        if not self._block:
            raise KeysNotSettedError(
                'For first you have to set keys via non_cipher_object.init()')
        else:
            if isinstance(self._block,tuple):
                password = self._block
            else:
                password = ''.join(self._block)
            try:
                if isinstance(what,(BufferedReader,TextIOWrapper)):
                    assert what.readable() #raises error if file not readable
                    if not run_in_processes:
                        what = FileByParts(what.name,'rb')

                if run_in_processes:
                    if cipher_process_count_for_now:
                        process_count = cipher_process_count_for_now
                    else:
                        process_count = self.cipher_process_count

                    if isinstance(what,str):
                        text_as_file = open('text_' + token_hex(4) + '.nc_temp','w')
                        text_as_file_name = text_as_file.name
                        text_as_file.write(what)
                        text_as_file.close()

                        what = open(text_as_file_name,'rb')

                    part_size = int(os.stat(what.name).st_size / process_count)

                    blocks_count = os.stat(what.name).st_size / (64*64)
                    block_as_flo = self.__get_hash_blocks(self._primary_hash,blocks_count=blocks_count)

                    if isinstance(block_as_flo,list):
                        raise TextTooSmallError('Your text too small for encryption in processes. Must be > 4096 symbols')

                    text_generator = FileByParts(what.name,'rb',part_size=part_size)
                    password_generator = FileByParts(block_as_flo.name,'rb',part_size=part_size)

                    queue = Queue() if not queue else queue
                    part_number = 0
                    while True:
                        try:
                            text_part_from_generator = next(text_generator)
                        except StopIteration: break

                        nc_object = NonCipher(primary_hash=self._primary_hash,
                            hash_of_input_data=self._hash_of_input_data)
                        nc_object.init()

                        nc_object.__cipher_process_part_number = part_number

                        with open('text_part_' + token_hex(4) + '.nc_temp','wb') as f:
                            f.write(text_part_from_generator)
                            text_part_temp_name = f.name

                        with open('block_part_' + token_hex(4) + '.nc_temp','wb') as f:
                            f.write(next(password_generator))
                            block_part_temp_name = f.name

                        nc_object._block = ('__EXECUTING_IN_PROCESSES__',block_part_temp_name)

                        Process(target=nc_object.cipher,
                            args=(text_part_temp_name,),
                            kwargs={'write_temp':True,'queue':queue}).start()

                        part_number += 1

                    block_as_flo.close()
                    text_generator.close()
                    password_generator.close()

                    encrypted_parts = []
                    while len(encrypted_parts) < part_number:
                        encrypted_parts.append(queue.get())
                    encrypted_parts.sort()

                    password_generator.remove()

                    total_encrypted_filename = token_hex(8) + '.ncfile'
                    for i in range(len(encrypted_parts)):
                        with open(total_encrypted_filename,'ab') as f:
                            encrypted_part = encrypted_parts.pop(0)
                            with open(encrypted_part[1],'rb') as e_part:
                                f.write(e_part.read())
                            os.remove(encrypted_part[1])

                    non_open = NonOpen(open(total_encrypted_filename,'rb'))
                    return (total_encrypted_filename,non_open)

                if write_temp:
                    path_check = '' if not isinstance(what,str) else what
                    if isinstance(what,bytes) or all(('.nc_temp' in path_check, os.path.exists(path_check))):
                        if isinstance(self.__cipher_process_part_number,int):
                            random_file_part = token_hex(8)
                            filename = str(self.__cipher_process_part_number).zfill(2) + '_' + token_hex(8) + '.nc_temp'
                            total_string = NonTempFile(string_type='bytes',filename=filename)
                        else:
                            total_string = NonTempFile(string_type='bytes')
                    else:
                        if isinstance(what,str) or 'b' not in what.mode:
                            total_string = NonTempFile(string_type='str',filename=token_hex(8) + '.ncfile')
                        else:
                            total_string = NonTempFile(string_type='bytes',filename=token_hex(8) + '.ncfile')
                else:
                    if isinstance(what,(TextIOWrapper,BufferedReader)):
                        total_string = b'' if 'b' in what.mode else ''
                    else:
                        total_string = b'' if isinstance(what,bytes) else ''

                if isinstance(self._block,tuple):
                    what = open(what,'rb')
                    block_from_file = open(self._block[1],'rb')
                    bytes_from_file = what.read(1)
                    while bytes_from_file:
                        total_string += bytes([ord(bytes_from_file) ^ ord(block_from_file.read(1))])
                        bytes_from_file = what.read(1)
                else:
                    index = 0
                    for symbols in what:
                        if len(password) == index:
                            self._block = self.__get_hash_blocks(self._block[-1].encode())
                            password = ''.join(self._block); index = 0

                        if isinstance(what,(str,GeneratorType)):
                            total_string += chr(ord(symbols) ^ ord(password[index]))

                        elif isinstance(what,bytes):
                            total_string += bytes([symbols ^ ord(password[index])])
                        else:
                            total_string += bytes([ord(symbols) ^ ord(password[index])])

                        index += 1

                if isinstance(self._block,tuple):
                    block_from_file.close()
                    os.remove(self._block[1])

                    what.close()
                    os.remove(what.name)

                if write_temp:
                    non_open = NonOpen(
                        open(total_string._temp_filename,total_string._read_type)
                    )
                    if queue:
                        queue.put(('__FROM_PROCESS__',total_string._temp_filename))
                    else:
                        return (total_string._temp_filename,non_open)
                else:
                    if queue:
                        queue.put(total_string)
                    else:
                        return total_string

            except Exception as e:
                raise NonCipherError('Error in NonCipher!', e,type(e))

if __name__ == '__main__':
    string = 'Hello, World!'

    nc_correct = NonCipher('password','secret_word',1000)
    nc_correct.init()
    encrypted_string = nc_correct.cipher(string)

    nc_incorrect = NonCipher('password','secret_word',1001)
    nc_incorrect.init()
    bad_decrypted_string = nc_incorrect.cipher(encrypted_string)

    print('> Correct Primary Hash:',nc_correct._primary_hash,'\n')
    print('>> Incorrect Primary Hash:',nc_incorrect._primary_hash,'\n')
    print('>>> Test:',[encrypted_string,bad_decrypted_string])
