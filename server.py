import socket               

s = socket.socket()         
host = socket.gethostname() 

port = 1274
s.bind((host, port))        

'''generate keys'''
import time
import datetime
import cPickle

from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto import Random

key = RSA.generate(1024)#, random_generator)
public_key=key.publickey()
to_send=cPickle.dumps(public_key)
hashofpuk=SHA512.new(to_send).hexdigest()
#print public_key


s.listen(5)                 
while True:
   c, addr = s.accept()     
   print 'server:Got connection from', addr, '\n'
   
   '''send public key to client'''
   c.send(hashofpuk)
   c.recv(1024)
   c.send(to_send)
   
   if c.recv(1024)=='1':
      c.close()
      print 'server:closing'
      continue   
   '''receive the file from client for timestamping'''
   ff=c.recv(1024)
   h1=ff
   while len(ff)==1024:
   	ff=c.recv(1024)
   	h1+=ff
   	print 'server:receiving hash of file from client......\n'
   print 'server:received hash of file\n'
   
   '''signing at server side and create signature'''
   ts=time.time()
   st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

   h2=SHA512.new(h1+st).hexdigest()
   #print h2 , st

   signature = key.sign(h2, '')
   print 'server:signature',signature
   '''send timestamp and  signature to client'''
   c.send(st)
   print c.recv(1024)
   c.send(str(signature[0]))
   print 'server:timestamp and signature sent'
   c.close()

