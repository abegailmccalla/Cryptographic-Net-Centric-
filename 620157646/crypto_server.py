# Server to implement the simplified RSA algorithm and receive encrypted
# integers from a client.
# The server waits for the client to say Hello. Once the client says hello,
# the server sends the client a public key. The client uses the public key to
# send a session key with confidentiality to the server.

# Author: Abegail McCalla
# Last modified: 2024-11-11
# Version: 0.1.1
#!/usr/bin/python3

import socket
import random
import math
import hashlib
import time
import sys
import simplified_AES
from NumTheory import NumTheory


class RSAServer(object):
    
    def __init__(self, port, p, q):
        self.socket = socket.socket()
        # The option below is to permit reuse of a socket in less than an MSL
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("", int(port)))
        self.socket.listen(5)
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		#For storing the server's n in the public/private key
        self.pubExponent = None	#For storing the server's e in the public key
        self.privExponent = None	#For storing the server's d in the private key
        self.nonce = None
        self.p = p
        self.q = q
        # Call the methods to compute the public private/key pairs
        
    def send(self, conn, message):
        conn.send(bytes(message,'utf-8'))

    def read(self, conn):
        try:
            data = conn.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Client is unavailable")
            
    def close(self, conn):
        print("closing server side of connection")
        try:
            conn.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f" {repr(e)}",
            )
        finally:
            # Delete reference to socket object
            conn = None    

    def RSAencrypt(self, msg):
        """Encryption side of RSA"""
        """"This function will return (msg^exponent mod modulus) and you *must*"""
        """ use the expMod() function. You should also ensure that msg < n before encrypting"""
        """You will need to complete this function."""
        """You will need to complete this function."""
        if msg < self.modulus:
            return NumTheory.expMod(msg,self.pubExponent,self.modulus)

    def RSAdecrypt(self, cText):
        """Decryption side of RSA"""
        """"This function will return (cText^exponent mod modulus) and you *must*"""
        """ use the expMod() function"""
        """You will need to complete this function."""
        return NumTheory.expMod(cText,self.privExponent,self.modulus)

    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext

    def generateNonce(self):
        """This method returns a 16-bit random integer derived from hashing the
            current time. This is used to test for liveness"""
        hash = hashlib.sha1()
        hash.update(str(time.time()).encode('utf-8'))
        self.nonce = int.from_bytes(hash.digest()[:2], byteorder=sys.byteorder)

    def findE(self, phi):
        """Method to randomly choose a good e given phi"""
        """You will need to complete this function."""
        cand_e = random.randint(2, phi - 1) #e candidate
        while not(NumTheory.gcd_iter(cand_e, phi) == 1 and cand_e < self.modulus):
            cand_e = random.randint(2, phi - 1)
        return cand_e #valid e
        
    def genKeys(self, p, q):
        """Generates n, phi(n), e, and d"""
        """You will need to complete this function."""
        # pubk = ()
        # prik = ()
        self.modulus = p*q #n
        phi = (p - 1) * (q - 1) #phi(n)
        self.pubExponent = self.findE(phi) #e
        d = NumTheory.ext_Euclid(phi, self.pubExponent) # d candidate
        if (NumTheory.expMod(self.pubExponent*d,1,phi) == 1):
            self.privExponent = d #valid d
            # pubk = (self.modulus, self.pubExponent)
            # prik = (self.modulus, self.privExponent)
            print("n: " + str(self.modulus))
            print("phi(n): " + str(phi))
            print("Public exponent e: " + str(self.pubExponent))
            print("Private exponent d: " + str(self.privExponent))

    def clientHelloResp(self):
        """Generates response string to client's hello message"""
        self.generateNonce()
        status = "102 Hello AES, RSA16, " + str(self.modulus) + ", " + \
         str(self.pubExponent) + ", " + str(self.nonce)
        return status

    def nonceVerification(self, decryptedNonce):
        """Verifies that the transmitted nonce matches that received
        from the client."""
        """You will need to complete this function."""
        if (decryptedNonce == self.nonce):
            return "104 Nonce Verified"
        return "400 Error"

    def start(self):
        """Main sending and receiving loop"""
        """You will need to complete this function"""
        while True:
            connSocket, addr = self.socket.accept() 
            #self.socket.connect((self.address, self.port))
            msg = connSocket.recv(1024).decode('utf-8') # received server's hello
            print ("Server's Hello Message: ", msg) 
            self.send(connSocket, self.clientHelloResp()) #sent client's hello
            print("Client's hello message has been sent") 
            self.read(connSocket) #received session key
            sessionKeyMsg = self.lastRcvdMsg
            print("Session Key: " + sessionKeyMsg)
            item = sessionKeyMsg.split(" ")
            self.sessionKey = self.RSAdecrypt(int(item[3])) #get session key from session key message
            encryptNonce = int(item[4]) #get nonce from session key message
            self.send(connSocket, self.nonceVerification(self.AESdecrypt(encryptNonce))) #sent nonce verification
            print("Nonce verification message has been sent")  
            if self.nonceVerification(self.AESdecrypt(encryptNonce)) == "400 Error":
                self.close(connSocket) 
                print("------Session Terminated------")
                sys.exit()
            else:
                self.read(connSocket) #received client's two integers
                intmsg = self.lastRcvdMsg
                print("Client Integer Message: ", intmsg) 
                ints = intmsg.split(" ")
                encryptp1 = int(ints[3]) #get first integer from integer message
                encryptp2 = int(ints[4]) #get second integer from integer message
                decryptp1 = self.AESdecrypt(encryptp1) #decrypt first integer from integer message
                decryptp2 = self.AESdecrypt(encryptp2) #decrypt second integer from integer message
                newSum = decryptp1 + decryptp2 #add integers
                sumencrypt = self.AESencrypt(newSum) #encrypt sum
                self.send(connSocket, "114 Composite Encrypted " + str(sumencrypt)) # sent composite encryption
                print("Sum of integers (composite message) has been sent") 
                self.read(connSocket) #received client's status message
                status = self.lastRcvdMsg
                print("Client Status Message: ", status) 

                self.read(connSocket) #received client's calculated server private key
                pk = self.lastRcvdMsg
                print("Server's Actual Private Key: " + str(self.privExponent))
                if int(pk) == self.privExponent: #check if received private key matches actual private key
                    status = "Yes, that is my private key"
                    self.send(connSocket, status)
                else:
                    status = "No, that is not my private key"
                    self.send(connSocket, status) #sent match status
                print("Private key verification sent to client")

            self.close(connSocket)
            print("------Session Terminated------")
            break

#Checks if value is prime
def isPrime(num1):
    if num1>1 and type(num1)==int:
        for n1 in range(2, num1):
            if (num1 % n1)==0:
                return False
            return True
    else:
        return False
        
def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 2:
        print ("Please supply a server port.")
        sys.exit()
        
    HOST = ''		# Symbolic name meaning all available interfaces
    PORT = int(args[1])     # The port on which the server is listening
    if PORT < 1023 or PORT > 65535:
        print("Invalid port specified.")
        sys.exit()
    print("Server of Abegail T. McCalla")

    #COLLECT PRIMES
    while True:
        print ("""Enter prime numbers. One should be between 211 and 281, and the other between 229 and 307. The product of your numbers should be less than 65536""")
        p = int(input('Enter P: '))   
        while not(isPrime(p)):
            print("Invalid number. Please enter a prime number.")
            p = int(input("Enter a prime number: "))
        q = int(input('Enter Q: '))
        while not(isPrime(q)):
            print("Invalid number. Please enter a prime number.")
            q = int(input("Enter a prime number: "))

        if ((211<=p<=281 and 229<=q<=307) or (211<=q<=281 and 229<=p<=307)) and (p*q<65536):
            break
        else: 
            print("Invalid entry.")

    server = RSAServer(PORT, p, q)
    server.genKeys(p, q) #generate keys
    print("Awaiting client connection...")
    server.start()   
    

if __name__ == "__main__":
    main()
