from base64 import encode
import sys
from PyQt6.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QTextEdit, QMessageBox
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import time

def genKeys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def encryptMessage(publicKey, valHash1):
    keyToEncrypt = RSA.import_key(publicKey)
    cipher = PKCS1_OAEP.new(keyToEncrypt)
    encryptedHash = cipher.encrypt(valHash1)
    return encryptedHash

def decryptMessage(privateKey, endcryptedHash):
    keyToDecrypt = RSA.import_key(privateKey)
    cipher = PKCS1_OAEP.new(keyToDecrypt)
    try:
        decryptedHash = cipher.decrypt(endcryptedHash)
    except:
        decryptedHash = bytes("Can't decrypt hash due to wrong key", encoding='utf-8')
    return decryptedHash

class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Digital sign")
        self.setFixedSize(1280,720)
        self.widgets()
        #always try to decyrpt using private key2, enctrypt always with public key1
        self.privateKey1, self.publicKey1 = self.privateKey2, self.publicKey2 = genKeys()
        self.paired = True     

    def widgets(self):
        #Label sections
        self.label1 = QLabel("Message A:", self)
        self.label2 = QLabel("Message B:", self)
        self.label3 = QLabel("Hash calculated from message A:", self)
        self.label4 = QLabel("Hash calculated from message B:", self)
        self.label5 = QLabel("Hash calculated from decrypted hash A:", self)
        self.label6 = QLabel("Are hash A and B is the same?:", self)
        #When executing program, keys are always paired, due to startup configuration
        self.label7 = QLabel("Are key paired?: True", self)
        self.label1.setGeometry(20,20,1000,20)
        self.label2.setGeometry(20,300,1000,20)
        self.label3.setGeometry(20,550,1000,20)
        self.label4.setGeometry(20,575,1000,20)
        self.label5.setGeometry(20,600,1000,20)
        self.label6.setGeometry(20,625,1000,20)
        self.label7.setGeometry(20,650,1000,20)
        
        #Button sections
        btn1 = QPushButton("Calculate haseh",self)
        btn1.clicked.connect(self.calcHashButton)
        btn2 = QPushButton("Generate new keypair for A",self)
        btn2.clicked.connect(self.newKeyPair1)
        btn3 = QPushButton("Pair key again",self)
        btn3.clicked.connect(self.pairKey)
        btn1.setGeometry(1160,650,100,50)
        btn2.setGeometry(990,650,150,50)
        btn3.setGeometry(820,650,150,50)

        #Text area section
        self.messageA = QTextEdit(self)
        self.messageA.setPlaceholderText("Type message that you are sending:")
        self.messageA.setGeometry(20,60,1240,200)
        self.messageB = QTextEdit(self)
        self.messageB.setPlaceholderText("Type message that you have recived:")
        self.messageB.setGeometry(20,340,1240,200)

    def calcHashButton(self):
        template1 = "Hash calculated from message A: "
        template2 = "Hash calculated from message B: "
        template5 = "Are hash A and B is the same?: "
        template3 = "Hash calculated from decrypted hash A: "
        #prepare hashes
        hash1 = SHA256.new()
        hash2 = SHA256.new()
        hash1.update(bytes(self.messageA.toPlainText(), encoding="utf-8"))
        hash2.update(bytes(self.messageB.toPlainText(), encoding="utf-8"))
        valHash1 = hash1.hexdigest()
        valHash2 = hash2.hexdigest() 
        #set hashes in labels
        self.label3.setText(template1 + hash1.hexdigest())
        self.label4.setText(template2 + hash2.hexdigest())
        #encrypt hash

        encryptedHash = encryptMessage(self.publicKey1.export_key(), bytes(valHash1, encoding='utf-8'))
        decryptedHash = decryptMessage(self.privateKey2.export_key(), encryptedHash).decode("utf-8")
        self.label5.setText(template3 + decryptedHash)

        isSame = False
        if(valHash2 == decryptedHash):
            isSame = True
        self.label6.setText(template5 + str(isSame))

    def newKeyPair1(self):
        popupMessage = QMessageBox()
        popupMessage.setWindowTitle("Atention!")
        popupMessage.setText("Keys will be changed!")
        popupMessage.exec()
        self.paired = False
        self.label7.setText("Are key paired?: " + str(self.paired))
        self.privateKey2, self.publicKey2 = genKeys()

    def pairKey(self):
        self.privateKey1, self.publicKey1 = self.privateKey2, self.publicKey2
        self.paired = True
        self.label7.setText("Are key paired?: " + str(self.paired))        


app = QApplication([])
window = Window()
window.show()
sys.exit(app.exec())