# DES-AES-Cryptography-with-Python

Python program to implement a 2 part code. 

Part 1 is to test the avalanche property of AES, i.e., how many bits of ciphertext change if we change just one bit of either the plaintext or the key. 

Part 2 is to implement 2 functions, one for encryption and another for decryption, where both read from a file and encrypt or decrypt respectively in both DES and AES. The scope has been limited to 16-bytes for sequences. 


                                **DATA ENCRYPTION STANDARD (DES).******
The Feistel (from the previous repository) is the building block of the Data Encryption Standard (DES). DES is a symmetric-key algorithm for the encryption of digital data. Although its short key length of 56 bits makes it too insecure for applications, it has been highly influential in the advancement of cryptography. DES is an implementation of a Feistel Cipher. It uses 16 round Feistel structure. The block size is 64-bit. 

Though, key length is 64-bit, DES has an effective key length of 56 bits, since 8 of the 64 bits of the key are not used by the encryption algorithm (function as check bits only). General Structure of DES is depicted in the following illustration

![image](https://user-images.githubusercontent.com/68347909/115646124-9673ff80-a2ef-11eb-9e45-6a8ff5bf5a3a.png)


DES satisfies both the desired properties of block cipher. These two properties make cipher very strong:

Avalanche effect − A small change in plaintext results in the very great change in the ciphertext.

Completeness − Each bit of ciphertext depends on many bits of plaintext.



                                **ADVANCED ENCRYPTION STANDARD (AES).******

Advanced Encryption Standard (AES) is a replacement for DES for better security. It is a symmetric block cipher, where the same key is used for encryption and decryption. It is found at least six time faster than triple DES. A replacement for DES was needed as its key size was too small. With increasing computing power, it was considered vulnerable against exhaustive key search attack.

Unlike DES, the number of rounds in AES is variable and depends on the length of the key. AES uses 10 rounds for 128-bit keys, 12 rounds for 192-bit keys and 14 rounds for 256-bit keys. Each of these rounds uses a different 128-bit round key, which is calculated from the original AES key.


 ![image](https://user-images.githubusercontent.com/68347909/115646481-36318d80-a2f0-11eb-84ad-bc05f7cdcd4c.png)


The initial transformation is just one operation. The rest of the rounds have 4 operations, and the last round has 3 operations. Initial round is simple addition. The plaintext and the key are added. In the next rounds, the operations are substitute bytes, shift rows, mix columns and add round keys. Mix columns and shift rows scramble the rows and columns. Substitute bytes mix the values of rows and columns together. Then round key is added.

Every stage is reversible. This is important for the decryption process. The state is the same at the end of each encryption/decryption phase, which means at the end of round 9 of encryption phase, it is the same output at round 1 of decryption. This is for easy retrieval. 



                                **MODE OF OPERATION.******
The mode of operation used here is ECB (Electronic Codebook). Each block of plaintext bit is encoded independently using the same key. It is typically used for secure transmission of single value (e.g. an encryption key). Data is broken into blocks of certain sizes. Each block of plaintext is applied to blocks with the same key to produce ciphertexts. Similarly, at the receiver side, each ciphertext block is applied to the same key to retrieve the plaintext. If P1 and P2 are the same content, then C1 and C2 are the same.


 ![image](https://user-images.githubusercontent.com/68347909/115646759-c4a60f00-a2f0-11eb-90ce-32d412a1cc57.png)

                           
