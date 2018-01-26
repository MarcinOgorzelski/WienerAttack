import math
import sys
from gmpy2 import *
import time

from Crypto.PublicKey import RSA


'''
	Klasa do importu kluczy publicznych
'''
class PublicKey():
	def __init__(self, path):
		self.n = None
		self.e = None
		self.path = path
		self.key = None
	# Importuj klucz z pliku
	def importkey(self):
		f = open(self.path, 'r')
		self.key = RSA.importKey(f.read())
		f.close()
		self.n = self.key.n
		self.e = self.key.e

	# Zaszyfruj dane
	def encryptdata(self, data):
		result = self.key.encrypt(data, len(data))
		return result

'''
	Klasa do eksportu kluczy prywatnych
'''
class PrivateKey():
        def __init__(self, n, e, d, p ,q):
                self.n = n
                self.d = d
		self.e = e
		self.p = p
		self.q = q
                self.path = "private.pem"
                self.key = RSA.construct((n, e, d, p, q))
	
        def exportkey(self):
		key = self.key.exportKey()
		f = open(self.path, "w")
		f.write(key)
		f.close()

        def decryptdata(self, data):
		result = self.key.decrypt(data)
		return result

'''
	Klasa udostepniajaca metody do przeprowadzenia ataku Wienera na RSA.

'''
class Wiener():
	def __init__(self, pubkey_path):
		# Sciezka do podatnego klucza publicznego
	  	self.path = pubkey_path	
		# Obiekt klucza publicznego oraz prywatnego
		self.pubKey = PublicKey(self.path)
		self.pubKey.importkey()
		self.privKey = None	
		self.p = None
		self.q = None
		
		
	def run(self):
		start = time.time()
		# Oblicz kolejne ulamki
		#print("[*] Oblicza ulamek ciagly")
		fractions = self.continued_fractions(self.pubKey.e, self.pubKey.n)
		#print("[*] Ulamki:")
		#print(fractions)
		# Oblicz kolejne wartosci ulamka lancuchowego
		convergents = self.calc_convergents(fractions)
		#print("[*] Kolejne konwergenty:")
		#print(convergents)
		# Znajdz szukany wykladnik prywatny
		d = self.find_key(self.pubKey.e, self.pubKey.n, convergents)	
		if d:
			# Stworz klucz prywatny
			self.privKey = PrivateKey(self.pubKey.n, self.pubKey.e, d, self.p, self.q)
			end = time.time()
			self.privKey.exportkey()	
			print("[*] Znaleziono klucz prywatny: ")
			print("[*] Znaleziona wartosc d : {}".format(d))
			print("[*] n: {}".format(self.pubKey.n))
			print("[*] p: {}".format(self.p))
			print("[*] q: {}".format(self.q))
			print("[*] Czas : {} s".format(end-start))
			print(self.privKey.key.exportKey())

	
	# Wyznacz ulamek ciagly. Funkcja zwraca  liste koljenych ulamkow
	def continued_fractions(self, e, n):
		r = 0
		temp = 0
		fractions = []
		while n != 0:
			r = e//n
			temp = e%n
			e = n
			n = temp
			fractions.append(r)	

		return fractions

	def calc_convergents(self, fractions):
		# Lista krotek w postaci (licznik, mianownik) czyli (k,d)
		convergents = []
		temp = []

		for i in range(1, len(fractions)+1):
			temp = fractions[0:i]
			k = temp[-1]
			d = 1
			for j in range(-2, -i-1, -1):
				# b + c/a = (b*a + c) / a
				k,d = temp[j]*k + d, k
					
			convergents.append((k, d))

		return convergents

	def find_key(self, e, n, convergents):
		for convergent in convergents:
			if self.check(e, n, convergent[0], convergent[1]):
				return convergent[1]
		return None

	def check(self, e, n, k, d):
		# Jezeli d jest parzyste, to proponowane wartosci sa zle
		if (k == 0) or (d % 2 == 0) or d==1:
			return False
		# Sprawdz czy phi(N) jest liczba calkowita
		if not((e*d-1) % k == 0):
			return False
		phi = long((e*d-1)/k)
		# Sprawdz czy rownanie x^2 - ( N - phi(N) +1)*x + N =0 ma calkowite rozwiazania
		b = long(n - phi + 1)
		delta = long(b*b - 4*n)
		if delta >= 0:
			vdelta = isqrt(mpz(delta))
			if not ((( -b - vdelta) % 2 == 0) and ((-b + vdelta) % 2 ==0)):
				return False
			self.p = abs(long((-b - vdelta)/2))
			self.q = abs(long((-b + vdelta)/2))
			return True

		return False
			 

if __name__  == "__main__":
	if len(sys.argv) != 2:
		print("[!] Sposob wywolania:")
		print("[!] {} <sciezka do klucza publicznego>".format(sys.argv[0]))
		sys.exit(0)

	attack = Wiener(sys.argv[1])
	attack.run()
