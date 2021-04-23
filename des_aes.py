#ENPM693 - Network Security
#Homework 4 - AES/DES
#April 21, 2021

UID = 116430197
Last_Name = "Mukam"
First_Name = "Kevin"


#------------------------------------------------------------------------------------------------------------
#---------------------------------  PART 1  -----------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

#Inverting the bit in the inputblock at the given position
def invert_bit(inputBit, b):
    result = ""
    if(inputBit[b] == '0'):
        result = inputBit[:b] + '1' + inputBit[b + 1:]  #inverting the bits at position b, because it's a string
    else:
        result = inputBit[:b] + '0' + inputBit[b + 1:]
    return result


#Finding the difference between the original cipher and inverted cipher
def findbitdiff(originalCipher, newCipher):
    diff = 0
    #print(len(originalCipher))
    for i in range (0, len(originalCipher)):
        #If the values at i are different, count
        if(originalCipher[i] != newCipher[i]):
            diff += 1
    return diff


def convertToBits(inputByte):
    inputBits = ""
    for b in inputByte:
        inputBits = inputBits + bin(b)[2:].zfill(8)
    return inputBits


#------------------------------------------------------------------------------------------------------------
#--------------------------------- Input Test  --------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------



def aes_input_av_test(inputblock, key, bitlist):
    # inputblock and key are 16 byte long bytes values each
    # bitlist is a list of integers that define the position of the
    # bit in the inputblock that needs to be inverted, one at a time, for example
    # [0, 3, 6, 25, 78, 127]

    # 1- any initializations necessary
    diff_list = []

    # Making sure the input is 16 bytes long.
    inputblock = pad(inputblock, 16)

    #Converting the input block to bit level
    inputBits = convertToBits(inputblock)

    # 2- perform encryption of the original values
    cipher = AES.new(key, AES.MODE_ECB)
    originalcipher = cipher.encrypt(inputblock) #Taking the ciphertext without the tag
    # print(originalcipher)
    originalCipherBits = convertToBits(originalcipher)  #Converting the ciphertext to bits
    # originalcipher = aes_enc(inputblock, key)

    #print(int(originalCipherBits, 2).to_bytes(16, "big"))
    # 3- for every value given in the bitlist:
    for b in bitlist:

        # invert the value of the corresponding bit in the inputblock
        newinput = invert_bit(inputBits, b)                 #Invert the bits in input bits at position b
        newinput = int(newinput, 2).to_bytes(16, "big")     #Convert it to bytes, 2:from binary to integer then to bytes
        # print(newinput)

        # perform encryption on the new input with one inverted bit at position b
        cipher = AES.new(key, AES.MODE_ECB)
        newcipher = cipher.encrypt(newinput)         #Encrypt in AES mode
        newcipherBits = convertToBits(newcipher) #Convert the encryption to bits

        # find the number of bit differences between the two ciphertexts
        # Use any method you like to find the difference.
        numbitdifferences = findbitdiff(originalCipherBits, newcipherBits)   #Check the difference between the input and the cipher

        # add it to the list
        diff_list.append(numbitdifferences)  #Add the differences to the list

    # return the list of numbers
    return diff_list



#------------------------------------------------------------------------------------------------------------
#--------------------------------- Key Test  --------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------




def aes_key_av_test(inputblock, key, bitlist):
    # inputblock and key are 16 byte values each
    # bitlist is a list of integers that define the position of the
    # bit in the key that needs to be inverted, one at a time, for example
    # [0, 3, 6, 25, 78, 127]

    # 1- any initializations necessary
    diff_list = []

    # Making sure the input is 16 bytes long.
    if len(key) < 16:
        key = pad(key, 16)
    # print(key)
    inputblock = pad(inputblock, 16)

    # Converting the input block to bit level
    keyBits = convertToBits(key)
    #print(keyBits)


    # 2- perform encryption of the original values
    cipher = AES.new(key, AES.MODE_ECB)
    originalcipher = cipher.encrypt(inputblock) # Taking the ciphertext without the tag
    originalCipherBits = convertToBits(originalcipher)  # Converting the ciphertext to bits

    # 3- for every value given in the bitlist:
    for b in bitlist:
        # invert the value of the corresponding bit in the key
        newKey = invert_bit(keyBits, b)  # Invert the bits in input bits at position b
        newKey = int(newKey, 2).to_bytes(16, "big")  # Convert it to bytes, 2:from binary to integer then to bytes
        # print(newinput)

        # perform encryption on the new input with one inverted bit at position b
        cipher = AES.new(newKey, AES.MODE_ECB)
        newcipher = cipher.encrypt(inputblock) # Encrypt in AES mode
        newcipherBits = convertToBits(newcipher)  # Convert the encryption to bits

        # find the number of bit differences between the two ciphertexts
        # Use any method you like to find the difference.
        numbitdifferences = findbitdiff(originalCipherBits, newcipherBits)  # Check the difference between the input and the cipher

        # add it to the list
        diff_list.append(numbitdifferences)  # Add the differences to the list

    # return the list of numbers
    return diff_list




#------------------------------------------------------------------------------------------------------------
#---------------------------------  PART 2  -----------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------


# plaintext = b'The quick brown fox jumps over the lazy dog'
# des_ciphertext = b'\x8b\xd3\x18\x8cN\xd1\xfc\xa54\xa9\xa2W\xb7\xd86\xb0pF\xca"\xa3I\xbf\xdb\x155\xff(!l{\\\x9bl\xb0\xee\xa9\xe2\x8b\x90\x13\xc1\xf8W\x04\xeb\x08\x08'
# aes_ciphertext = b'j*,\x9a5\xab\xec\xb3f\xdf&%\xbd\xda\xe5\xb8\x05\x1c\xc7d\x0e\x91\xe2*wtg\x02d\x81R{\xd4V\x1a\x0b]\x06\xe9\x9c"M\xfch\x1d\xb4\x05\xaa'
# f = open('input.txt','wb')
# f.write(plaintext)
# f.close()
# f = open('des_input.txt','wb')
# f.write(des_ciphertext)
# f.close()
# f = open('aes_input.txt','wb')
# f.write(aes_ciphertext)
# f.close()


#------------------------------------------------------------------------------------------------------------
#---------------------------------  Encryption  -------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------

from Crypto.Cipher import DES


def encrypt_file(inputfile, des_key, aes_key, des_output_file, aes_output_file):
    # This function should create 2 output files. One with DES encryption, and the other with AES encryption.

    # Open a read file handler for the input file.
    finp = open(inputfile, 'rb')
    # rb stands for read bytes.
    # Then read the bytes from the file and store them in a variable.
    filebytes = finp.read()
    # Then close the file.
    finp.close()

    #Split into 8-bytes each, and padding the last 8-bits with spaces \x20
    des_plain_text = [filebytes[i:i + 8] for i in range(0, len(filebytes), 8)]
    if (len(des_plain_text[-1]) < 8):
        des_plain_text[-1] = pad(des_plain_text[-1], 8)
    # print(des_plain_text)

    #Encrypting in DES, ECB mode
    cipher = DES.new(des_key, DES.MODE_ECB)
    des_ciphertext = b''
    for i in range(0, len(des_plain_text)):
        des_ciphertext += (cipher.encrypt(des_plain_text[i]))
    # print(des_ciphertext)
    '''
    For DES:
    in a loop, break filebytes into 8 bytes chunks and pad the last set of bytes if the length is not 8
    run encryption for each block of 8 bytes
    Then write the final ciphertext in the output file
    '''

    fout_des = open(des_output_file, 'wb')
    # wb stands for write bytes
    fout_des.write(des_ciphertext)
    fout_des.close()

    '''
    For AES:
    in a loop, break filebytes into 16 bytes chunks and pad the last set of bytes if the length is not 16
    run encryption for each block of 16 bytes
    Then write the final ciphertext in the output file
    '''

    #Encrypting in AES
    aes_plain_text = [filebytes[i:i + 16] for i in range(0, len(filebytes), 16)]  # Split into 16-bytes each
    if (len(aes_plain_text[-1]) < 16):
        aes_plain_text[-1] = pad(aes_plain_text[-1], 16)
    # print(aes_plain_text)

    cipher = AES.new(aes_key, AES.MODE_ECB)
    aes_ciphertext = b''
    for i in range(0, len(aes_plain_text)):
        aes_ciphertext += (cipher.encrypt(aes_plain_text[i]))
    # print(aes_ciphertext)

    fout_aes = open(aes_output_file, 'wb')
    # wb stands for write bytes
    fout_aes.write(aes_ciphertext)
    fout_aes.close()

    return 0




#------------------------------------------------------------------------------------------------------------
#---------------------------------  Decryption  -------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------

from Crypto.Util.Padding import pad, unpad


def decrypt_file(des_input_file, aes_input_file, des_key, aes_key, des_output_file, aes_output_file):
    # This function should create 2 output files. One for DES decryption, and the other for AES decryption.


    # Open a read file handler for the DES ciphertext input file.
    finp_des = open(des_input_file, 'rb')
    # rb stands for read bytes.
    # Then read the bytes from the file and store them in a variable.
    filebytes_des = finp_des.read()
    # Then close the file.
    finp_des.close()

    '''
    For DES:
    in a loop, break filebytes into 8 bytes chunks
    run decryption for each block of 8 bytes
    Then write the final plaintext in the output file
    '''
    des_cipher_text = [filebytes_des[i:i + 8] for i in range(0, len(filebytes_des), 8)]
    # print(des_cipher_text)
    decipher = DES.new(des_key, DES.MODE_ECB)

    des_plaintext = b''
    for i in range(0, len(des_cipher_text)):
        des_plaintext += (decipher.decrypt(des_cipher_text[i]))
    # print(des_plaintext)

    des_plaintext = unpad(des_plaintext, 16) #Unpading

    fout_des = open(des_output_file, 'wb')
    # wb stands for write bytes
    fout_des.write(des_plaintext)
    fout_des.close()

    # Open a read file handler for the AES ciphertext input file.
    finp_aes = open(aes_input_file, 'rb')
    # rb stands for read bytes.
    # Then read the bytes from the file and store them in a variable.
    filebytes_aes = finp_aes.read()
    # Then close the file.
    finp_aes.close()

    '''
    For AES:
    in a loop, break filebytes into 16 bytes chunks
    run decryption for each block of 16 bytes
    Then write the final plaintext in the output file
    '''
    aes_cipher_text = [filebytes_aes[i:i + 16] for i in range(0, len(filebytes_aes), 16)]
    # print(aes_cipher_text)
    decipher = AES.new(aes_key, AES.MODE_ECB)

    aes_plaintext = b''
    for i in range(0, len(aes_cipher_text)):
        aes_plaintext += (decipher.decrypt(aes_cipher_text[i]))
    # print(aes_plaintext)

    aes_plaintext = unpad(aes_plaintext, 16)  # Unpading

    fout_aes = open(aes_output_file, 'wb')
    # wb stands for write bytes
    fout_aes.write(aes_plaintext)
    fout_aes.close()

    return 0





#------------------------------------------------------------------------------------------------------------
#--------------------------------- Main Code  --------------------------------------------------------------
#------------------------------------------------------------------------------------------------------------


#Main code with testing
if __name__ == "__main__":

    print("-------------------------------- Homework 4 --------------------------------")
    print("")
    print("----------------------------------------------------------------------------")
    print("---------------------------------- PART 1 ----------------------------------")
    print("----------------------------------------------------------------------------")
    print("")
    print("-------------------------------- Input Test --------------------------------")
    print(aes_input_av_test(b'solongpadawan', b'verynicelongbyte', [0, 29, 68, 100, 127]))

    print("")
    print("--------------------------------- Key Test ---------------------------------")
    print(aes_key_av_test(b'solongpadawan', b'verynicelongbyte', [0, 29, 68, 100, 127]))

    print("")
    print("----------------------------------------------------------------------------")
    print("---------------------------------- PART 2 ----------------------------------")
    print("----------------------------------------------------------------------------")
    print("")

    print("-------------------------------- Encryption ---------------------------------")
    print(encrypt_file('input.txt',b'nicebyte',b'verynicelongbyte','des_output_e.txt','aes_output_e.txt'))

    print("")
    print("-------------------------------- Decryption ---------------------------------")
    decrypt_file('des_input.txt', 'aes_input.txt', b'nicebyte', b'verynicelongbyte', 'des_output_d.txt', 'aes_output_d.txt')

    print("")
    print("----------------------------------------------------------------------------")
    print("-------------------------------- The End ---------------------------------")
    print("----------------------------------------------------------------------------")