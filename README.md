# <h2> NonCipher - The encryption algorithm that was based on [SafePassword](https://bit.ly/SafePassword).

* **SafePassword(SP) is an incredibly simple program, the meaning of which rolls down only in one loop. Please read the basic code at the link above, since SP is the main thing in this program.**

# <h5> You can easy install NonCipher via pip
`pip install --upgrade NonCipher`

First of all, **three arguments** are passed to the main NonCipher class: **password**, **secret word**, **number of iterations**. 

The **secret_word** in the hashing language is, in fact, salt.

```
from NonCipher import NonCipher
nc = NonCipher ('password', 'secret_word', 1)
```

The line above in pseudocode looks like this:
```
for _ in range(iterations{1}):
    password_hash = sha256(password_hash)
```

In NonCipher, I called the very first hash "__input hash__(or __input key__, if you like it)"

To create an **input hash** you need to use the class method `init()`
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()
```
This is worth paying attention to, since the more iterations there are(*__in our case, only one for example, never do it for God's sake. Ok? Ok.__*) the longer(obviously) it takes time to create an **input hash**. 

If you are ready to wait, **you can set up > 500,000, so only 1/3 of your input hash may take quite a long time to pick up.**
After initialization, you can view your **input hash**, and make sure that it is impossible to pick it up(if you don't have a supercomputer, lol)
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

print(nc._password_hash)
```
Also you can see the hash of your input(**password**, **secret_word**, **iterations**), it is also important, and later I will explain why

`print(nc._hash_of_nc_setup)`

# <h3> What's next?

Next, another 64 is created from the **input hash**, they form the first list of hashes, from which a single **password of 4096 characters** is obtained during encryption.

And they are created like this:
```
hash = self._password_hash
self._keys_for_cipher = [
    self.get_hash_of(
        hash, self._hash_of_nc_setup, ord(i)
    )
    for i in decoded_hash
]
```
**If the text is longer than 4096 characters - NonCipher will create a new selection of hashes from the last existing** `self._keys_for_cipher`, similar to the **input hash**. And then everything is encrypted with a simple [XOR algorithm](https://en.m.wikipedia.org/wiki/XOR_cipher).

In fact, it was a complete description of the algorithm. I came up with it myself(but it definitely already exists, lol), and it seems to me that this algorithm is **crypto-resistant. If you want to try to decrypt the text encrypted by this program, use the constant TRY_TO_DECRYPT**
```
from NonCipher import NonCipher, TRY_TO_DECRYPT

nc = NonCipher (?,?,?)
nc.init()

print(nc.cipher(TRY_TO_DECRYPT))
```
# <h3> In the meantime, you are trying to decipher it(right? Really, yes? Yes??) I will describe here examples of using NC.

First: `nc.init()` is required. Since without this, the **input hash will not be created**, which means that **using** the main function for which we have gathered here(nc.cipher(..)) will be **impossible**.


# <h4> Encryption string length <= 4096
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

string = 'Hello, World!'

encrypted_string = nc.cipher(string) # Encrypted symbols
decrypted_string = nc.cipher(encrypted_string) # Hello, World!
```
Because the basis of NC is the [XOR algorithm](https://en.m.wikipedia.org/wiki/XOR_cipher) - **one function both encrypts and decrypts strings**.


# <h4> Encryption strings length > 4096
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

string = 'Hello, World! ............' # > 4096

encrypted_string = nc.cipher(string) # Encrypted symbols
decrypted_string = nc.cipher(encrypted_string) # Encrypted symb ... stop what?
```
Exactly! If you have encrypted a string that is **more than 4096 characters, you need to call the class method** `nc.init()` **again**, since in `nc._keys_for_cipher` there are hashes left from the last hash in the last collection(difficult, yes). I have already said that if a text with a length > 4096 a new selection of hashes from the last existing one will be created. After encryption, they are not reset. That makes sense, I'm sure.

I explained something similar in the code itself, and you can **use the help function** at any time. Just do `help(nc.init)`


And in order for the code to be correctly decrypted, you need to do this:
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

string = 'Hello, World! ............' # > 4096

encrypted_string = nc.cipher(string) # Encrypted symbols
nc.init()
decrypted_string = nc.cipher(encrypted_string) # Hello, World ..........
```
# <h4> File Encryption

**NC can encrypt any files** _if you have time for her(lenny)_.
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

file_bytes = open('cats.png', 'rb').read()

encrypted_file = nc.cipher(file_bytes)
nc.init() # if your file weighs more than 4096 bytes
decrypted_file = nc.cipher(encrypted_string)
```
__*It looks simple, but am I going to keep a 500-mb file in RAM? Are you an idiot?__*

NC can write encrypted characters **to a file instead of being stored in memory**. For this, it is worthwhile to simply put **kwarg** `write_temp` to `True`. In some cases, because of this, the encryption speed increases. If `write_temp` is set to `True`, `nc.cipher(..)` returns a two-element tuple: **the name of the temporary file, a file-like object that is ready to read.** After reading the file_like object, **the temporary file will be deleted.** If you **don't** want this, set `remove_temp` to `False`. Below is an example.
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

file_bytes = open('cats.png', 'rb').read()

encrypted_file = nc.cipher(file_bytes, write_temp=True) # Two-element tuple

encrypted_string = encrypted_file[1].read() # Temporary file is deleted
```
Or

`encrypted_string = encrypted_file[1].read(remove_temp=False) # Temporary file is not deleted`

# <h4> Multiprocessing

To begin, you create a NonCipher class object with the standard configuration, after you have executed the `nc.init()` method - take two necessary parameters from there that will allow you to implement multi(processing/threading) `nc._password_hash`,`nc.hash_of_nc_setup`.

After that you will be able to create a new object of the NonCipher class in each process, and pass the **input hash** and the NonCipher **setup hash** to the same arguments.  After `nc.init()` execution, the input hash will not be created, but the one you entered will be used, which means you do not need to wait for the time to create the **input hash**

My example below
```
from NonCipher import NonCipher
from multiprocessing import Process

nc = NonCipher('password','secret_word',1)
nc.init()

nc_password_hash = nc._password_hash
nc_hash_of_nc_setup = nc._hash_of_nc_setup

file = open('picture.jpg','rb').read()

def nc_process_test(ph,hons):
    nc = NonCipher(password_hash=ph,
        hash_of_nc_setup=hons)
    nc.init()
    
    print(nc.cipher(file,write_temp=True))

for i in range(5):
    args = (nc_password_hash,nc_hash_of_nc_setup)
    Process(target=nc_process_test,args=args).start()
```
# <h5> It seems that this is all. More detailed information about each method of each NonCipher class can be obtained using the built-in function Python `help(NonCipher)`.

**Open Issue, swear my English, and also don't forget - PHP is trash.**
