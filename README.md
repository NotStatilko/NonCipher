# <h2> NonCipher - The encryption algorithm that was based on [SafePassword](https://pastebin.com/srfVetG6).

* **SafePassword is an incredibly simple program, the meaning of which rolls down only in one loop. Please read the basic code at the link above, since SafePassword is the main thing in this program.**

# <h5> You can easy install NonCipher via pip
`pip install -U NonCipher`

First of all, **three arguments** are passed to the main NonCipher class: **password, secret word, number of iterations**.

The **secret_word** in the hashing language is, in fact, **salt**.

```
from NonCipher import NonCipher
nc = NonCipher('password', 'secret_word', 1)
```

The line above in pseudo-code looks like this:
```
for _ in range(iterations{1}):
    primary_hash = sha256(primary_hash)
return sha512(primary_hash)
```

In NonCipher, I called the very first hash "__primary hash__"

To create a **primary hash** you need to use the class method `.init()`
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()
```
This is worth paying attention to, since the more iterations there are(*__in our case, only one for example, never do it for God's sake. Ok? Ok.__*) the longer(obviously) it takes time to create an **primary hash**.

If you are ready to wait, you can set up > **5,000,000**, **so only 1/3 of your primary hash may take quite a long time to pick up**.
After initialization, you can view **your primary hash**, and make sure that it is impossible to pick it up.
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

print(nc._primary_hash)
```
Also you can see the hash of your input data(**password**, **secret_word**, **iterations**), it is also important, and later I will explain why

`print(nc._hash_of_input_data)`

# <h3> What's next?

Next, another 64 is created from the **primary hash**, they form the first list of hashes, from which a single **password of 4096 characters** is obtained during encryption.

And they are created like this(pseudocode):
```
unique_numbers = set([
    *sha256(self._primary_hash).digest(),
    *sha256(self._hash_of_input_data).digest(),
    *sha256(self._primary_hash + self._hash_of_input_data).digest()
])
self._block = [
    get_hash_of(
        self._primary_hash, self._hash_of_input_data, i
    )
    for i in list(unique_numbers)[:64]
]
```
**If the text is longer than 4096 characters — NonCipher will create a new selection of hashes(new block) from the last existing** `self._block`, similar to the **primary hash**. And then everything is encrypted with a simple [XOR algorithm](https://en.m.wikipedia.org/wiki/XOR_cipher).

In fact, it was a complete description of the algorithm. I came up with it myself(but it definitely already exists, lol), and it seems to me that this algorithm is crypto-resistant. If you want to try to decrypt the text encrypted by this program, use the constant `TRY_TO_DECRYPT`
```
from NonCipher import NonCipher, TRY_TO_DECRYPT

nc = NonCipher(?,?,?)
nc.init()

print(nc.cipher(TRY_TO_DECRYPT))
```
# <h3> In the meantime, you are trying to decipher it(right? Really, yes? Yes??) I will describe here examples of using NC.

Firstly: `nc.init()` is required. Since without this, the **primary hash** will not be created, which means that using the main function for which we have gathered here(`nc.cipher(..)`) will be impossible.


# <h4> Encryption string length <= 4096
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

string = 'Hello, World!'

encrypted_string = nc.cipher(string) # Encrypted symbols
decrypted_string = nc.cipher(encrypted_string) # Hello, World!
```
Because the basis of NC is the [XOR algorithm](https://en.m.wikipedia.org/wiki/XOR_cipher) — **one function both encrypts and decrypts strings**.

# <h4> Encryption strings length > 4096
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

string = 'Hello, World! ............' # > 4096

encrypted_string = nc.cipher(string) # Encrypted symbols
decrypted_string = nc.cipher(encrypted_string) # Encrypted symb ... stop what?
```
Exactly! If you have encrypted a string that is **more than 4096 characters, you need to call the class method** `nc.init()` **again**, since in `nc._block` there are hashes left from the last hash in the last collection(difficult, yes). I have already said that if a text with a length > 4096 a new selection of hashes from the last existing one will be created. After encryption, they are not reset. That makes sense, I'm sure.

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
# <h2> File Encryption

**NC can encrypt any files**(_if you have time for her_( ͡° ͜ʖ ͡°)).
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

with open('cats.png', 'rb') as f:
    encrypted_file = nc.cipher(f)
    nc.init() # if your file weighs more than 4096 bytes
    decrypted_file = nc.cipher(encrypted_file)
```
__*It looks simple, but am I going to keep a 500-mb file in RAM? Are you an idiot?*__

NC can write encrypted characters **to a file instead of being stored in memory**. For this, it is worthwhile to simply put **kwarg** `write_temp` to `True`. In some cases, because of this, the encryption speed increases. If `write_temp` is set to `True`, `nc.cipher(..)` returns a two-element tuple: **the name of the .ncfile file, a file-like object that is ready to read.** After reading the file_like object, **the temporary file will be deleted.** If you **don't** want this, set `remove_temp` to `False`. Below is an example.
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

with open('cats.png', 'rb') as f:
    encrypted_file = nc.cipher(f, write_temp=True) # Returns two-element tuple
    encrypted_string = encrypted_file[1].read() # Temporary file will be removed after read
```
Or if you don't want the temporary file to be deleted:

```
encrypted_string = encrypted_file[1].read(remove_temp=False) # Temporary file is not removed
```

# <h2> Multiprocessing

To begin, you create a NonCipher class object with the standard configuration, after you have executed the `nc.init()` method - take two necessary parameters from there that will allow you to implement multi(processing/threading) `nc._primary_hash`,`nc.hash_of_input_data`.

After that you will be able to create a new object of the NonCipher class in each process, and pass the **primary hash** and the NonCipher **hash of input data** to the same arguments. After `nc.init()` execution, the **primary hash** will not be created, but the one you entered will be used, which means you don't need to wait for the time to create the **primary hash**

My example below
```
from NonCipher import NonCipher
from multiprocessing import Process

nc = NonCipher('password','secret_word',1)
nc.init()

def nc_process_test(file,ph,hoid):
    nc = NonCipher(primary_hash=ph, hash_of_input_data=hoid)
    nc.init()
    print(nc.cipher(file,write_temp=True))

if __name__ == '__main__':
    for i in range(5):
        args = (open('cats.png'),nc._primary_hash,nc._hash_of_input_data)
        Process(target=nc_process_test,args=args).start()
```

# <h2> NCv4.X and encryption in different processes

NCv4.X now has the ability to encrypt and decrypt files in **different processes** to speed up NonCipher.
```
from NonCipher import NonCipher

nc = NonCipher('password', 'secret_word', 1)
nc.init()

if __name__ == '__main__':
    with open('test.png') as f:
        print(nc.cipher(f, run_in_processes=True))
```
A new variable has appeared in the NonCipher class — `nc.cipher_process_count`. You can set the number of processes more or less, depending on the power of your computer. By default, `nc.cipher_process_count` is 10.

Firstly, a single password is created from all blocks; after, this password is divided into `nc.cipher_process_count` files, along with the data to be encrypted(text or file). Each such file is allocated its own part of the password with which this part of the file is encrypted. After the end of the encryption process, all the numbered parts are **assembled into one common encrypted file**.
This file can be decrypted both by the **"processor"** and the **default** methods.

I, perhaps, will not go into big details. You can always look at the code, or open the Issue and ask.

# <h4> Bitcoin address for support <3
```
bc1qksvmzhjy79z85v035ehdq4v9tcfqgaqq7jga8a
```

# <h4> It seems that this is all. More detailed information about each method of each NonCipher class can be obtained using the built-in function Python `help(NonCipher)`.

**Open Issue, swear my English, and also don't forget - All programming languages is good;)**
