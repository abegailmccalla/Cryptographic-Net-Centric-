# Client to implement simplified RSA algorithm and then subsequently send
# encrypted prime numbers to a server. The client says hello to the server
# and indicates
# which cryptographic algorithms it can support. The server picks one
# asymmetric key and one symmetric key algorithm and then responds to the
# client with its public key and a nonce. The client generates a symmetric
# key to send to the server, encrypts the symmetric key with the public key,
# and then encrypts the nonce with the symmetric key.
# If the nonce is verified, then the server will send the "104 Nonce Verified"
# message.

import socket
import math
import random
import sys
import simplified_AES
from NumTheory import NumTheory

# Author: Abegail McCalla
# Last modified: 2024-11-11
# Version: 0.1
#!/usr/bin/python3

class RSAClient:
    def __init__(self, address, port):
        self.address = address
        self.port = int(port)
        self.socket = socket.socket()
        self.lastRcvdMsg = None
        self.sessionKey = None		#For storing the symmetric key
        self.modulus = None		    #For storing the server's n in the public key
        self.serverExponent = None	#For storing the server's e in the public key

    def connect(self):
        self.socket.connect((self.address, self.port))

    def send(self, message):
        self.socket.send(bytes(message,'utf-8'))

    def read(self):
        try:
            data = self.socket.recv(4096).decode('utf-8')
        except BlockingIOError:
            pass
        else:
            if data:
                self.lastRcvdMsg = data
            else:
                raise RuntimeError("Server is unavailable")

    def close(self):
        print("closing connection to", self.address)
        try:
            self.socket.close()
        except OSError as e:
            print(
                "error: socket.close() exception for",
                f"{self.address}: {repr(e)}",
            )
        finally:
            # Delete reference to socket object for garbage collection
            self.socket = None

    def RSAencrypt(self, msg):
        """"This function will return (msg^exponent mod modulus) and you"""
        """ *must* use the expMod() function. You should also ensure that"""
        """  msg < n before encrypting"""
        """You will need to complete this function."""
        if msg < self.modulus:
            return NumTheory.expMod(msg,self.serverExponent,self.modulus)

    def computeSessionKey(self): #generate a suitable session key
        """Computes this node's session key"""
        """Update this method such that you are guaranteed correct results"""
        self.sessionKey = random.randint(1, 65536) 

    def AESencrypt(self, plaintext):
        """Computes the simplified AES encryption of some plaintext"""
        simplified_AES.keyExp(self.sessionKey) # Generating round keys for AES.
        ciphertext = simplified_AES.encrypt(plaintext) # Running simplified AES.
        return ciphertext
    
    def AESdecrypt(self, cText):
        """Decryption side of AES"""
        simplified_AES.keyExp(self.sessionKey)
        return simplified_AES.decrypt(cText)

    def serverHello(self):
        status = "101 Hello 3DES, AES, RSA16, DH16"
        return status
    
    def sessionKeyMsg(self, nonce): #session key message
        """Function to generate response string to server's hello"""
        self.computeSessionKey()
        return "103 Session Key " + str(self.RSAencrypt(self.sessionKey)) + " " + str(self.AESencrypt(nonce))
    
    def compute_private_key(self, e, n): #compute server's private key
        def factorize_n(n): # This is a simple factorization approach for n 
            for i in range(2, n): 
                if n % i == 0: 
                    return i, n // i 
            raise Exception('Failed to factorize n')
        p, q = factorize_n(n) 
        phi = (p - 1) * (q - 1) #find phi(n)
        d = NumTheory.ext_Euclid(phi, e) #find private exponent d
        return d

    def start(self):
        """Main sending and receiving loop for the client"""
        self.connect()
        self.send(self.serverHello()) #sent server's hello
        print("Server's hello message has been sent")
        self.read() #received client's hello
        hello = self.lastRcvdMsg
        print("Client's Hello Message: ", hello)
        keys = hello.split(",")
        self.modulus = int(keys[2]) #get n from client's hello
        self.serverExponent = int(keys[3]) #get server exponent e from client's hello
        server_nonce = int(keys[4]) #get nonce from client's hello
        self.send(self.sessionKeyMsg(server_nonce)) #sent session key
        print("Session key has been sent")
        self.read() #received nonce verification
        noncemsg = self.lastRcvdMsg
        print("Nonce Verification: ", noncemsg)
        if noncemsg == "104 Nonce Verified":
            print("Enter two integers") #collect two integers
            i1 = int(input("Enter the first integer: "))
            i2 = int(input("Enter the second integer: "))
            sumi = i1 + i2 #sum two integrs
            encryptp1 = self.AESencrypt(i1) #encrypt integer 1
            encryptp2 = self.AESencrypt(i2) #encrypt integer 2
            self.send("113 Integers Encrypted " + str(encryptp1) + " " + str(encryptp2)) #sent encrypted integers
            print("Integers sent to server")
            self.read() #received composite message
            serversumi = self.lastRcvdMsg
            summsg = serversumi.split(" ")
            print("Server Composite Message: ", serversumi)
            comp = self.AESdecrypt(int(summsg[3])) #encrypted sum from composite message and decrypt it
            if comp == sumi: #check if received sum matches calculated sum
                status = "200 OK"
                self.send(status)
            else:
                status = "400 Error"
                self.send(status) #sent match status
            print("Status code sent to server")

            #CHECK SERVER'S PRIVATE KEY
            spk = self.compute_private_key(self.serverExponent, self.modulus)
            self.send(str(spk))
            print("Server, is this your private key: " + str(spk))
            self.read() #received composite message
            status = self.lastRcvdMsg
            print(status) 

        self.close()
        print("------Session Terminated------")


def main():
    """Driver function for the project"""
    args = sys.argv
    if len(args) != 3:
        print ("Please supply a server address and port.")
        sys.exit()
    print("Client of Abegail T. McCalla")
    serverHost = str(args[1])       # The remote host
    serverPort = int(args[2])       # The same port as used by the server

    client = RSAClient(serverHost, serverPort)
    try:
        client.start()
    except (KeyboardInterrupt, SystemExit):
        exit()

if __name__ == "__main__":
    main()
