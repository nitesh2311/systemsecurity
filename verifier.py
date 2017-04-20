import socket,time               
import datetime

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto import Random

import hashlib
s = socket.socket()     

host = socket.gethostname() 
port = 1274
s.connect((host, port))


'''receive public key from server'''

import cPickle
hashofpuk=s.recv(1024)
s.send('ok')
Picklekey=s.recv(1024)
if hashofpuk!=SHA512.new(Picklekey).hexdigest():
	s.send('1')
	s.close()
	print 'Public key not valid'
	exit(0)
print 'public_key valid'

public_key=cPickle.loads(Picklekey)
s.send('1')
s.close()



BLOCKSIZE=65536

'''import the signature and timestamp'''
fname='r.pdf'

f=open(fname.split('.')[0]+'signature.txt','rb')
lines=f.readlines()
f.close()

sig=(long(lines[0][0:-1]),)
stt=lines[1]

'''now verify'''

hh=hashlib.sha512()
with open(fname,'rb') as f1:
	buf= f1.read(BLOCKSIZE)
	while len(buf)>0:
		hh.update(buf)
		buf=f1.read(BLOCKSIZE)
h11 = hh.hexdigest()		


h22=SHA512.new(h11+stt).hexdigest()


print 'verified:',public_key.verify(h22, sig)
