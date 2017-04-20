import socket,time               
import time
import datetime

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto import Random

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

s.send('2')

'''convert file into hash file at client side'''


fname = 'r.pdf'

import hashlib
BLOCKSIZE=65536

h=hashlib.sha512()
with open(fname,'rb') as f:
	buf= f.read(BLOCKSIZE)
	while len(buf)>0:
		h.update(buf)
		buf=f.read(BLOCKSIZE)
h1 = h.hexdigest()		
#print 'h1',h1
'''Now send the hashed file to Timestamping Server for timestamping'''

s.send(h1)

'''receive time stamp and signature from TSS'''

st=s.recv(1024)

s.send('client : time stamp received ok')
ff=s.recv(1024)
ss=ff
while len(ff)==1024:
	ff=s.recv(1024)
   	ss+=ff
   	print 'client:receiving signature from server.....\n'
print 'client:received signature\n'

signature=(long(ss),)

'''now add the signature and timestamp to the new text file for 
verification'''

f=open(fname.split('.')[0]+'signature.txt','w')
f.write(ss+'\n'+st)
f.close()

'''timestamping done............'''
print 'client:doc timestamped'

'''wait for modifying the document'''
time.sleep(10)

'''verify at client side'''

f=open(fname.split('.')[0]+'signature.txt','rb')
lines=f.readlines()
f.close()

sig=(long(lines[0][0:-1]),)
stt=lines[1]

hh=hashlib.sha512()
with open(fname,'rb') as f1:
	buf= f1.read(BLOCKSIZE)
	while len(buf)>0:
		hh.update(buf)
		buf=f1.read(BLOCKSIZE)
h11 = hh.hexdigest()		


h22=SHA512.new(h11+stt).hexdigest()

print 'verified:',public_key.verify(h22, sig)

s.close()