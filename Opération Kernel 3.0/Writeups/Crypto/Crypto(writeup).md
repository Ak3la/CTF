# Writeup : Crypto (crypto)
###### by Ak3la 
### CTF : Operation Kernel (2022) / Challenge crypto, 100 pts


L'objectif de ce challenge est de retrouver le flag au format : HACK{...}
Il nous est donné 2 fichiers, le fichier chiffré contenant le flag `CONFIDENTIEL.xlsx.ecn` ainsi que l'algorithme qui a permis de chiffrer ce fichier `encrypt.py`

## Étude du programme de chiffrement
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import  argparse
import  hashlib
import  random

sbox = [225, 215, 45, 11, 70, 238, 109, 46, 159, 235, 57, 173, 90, 53, 85, 114, 245, 40, 78, 2, 71, 229, 199, 201, 58, 42, 177, 76, 210, 246, 12, 27, 26, 208, 243, 73, 92, 200, 206, 102, 217, 207, 17, 14, 147, 101, 170, 32, 10, 255, 80, 82, 24, 61, 95, 43, 124, 122, 216, 115, 205, 218, 75, 227, 239, 175, 152, 113, 74, 224, 248, 194, 97, 155, 91, 125, 249, 3, 25, 51, 103, 213, 204, 104, 63, 244, 145, 44, 160, 106, 21, 94, 222, 48, 121, 165, 171, 202, 31, 203, 29, 230, 156, 240, 168, 34, 129, 182, 234, 185, 241, 123, 33, 163, 15, 9, 0, 99, 7, 178, 49, 186, 154, 126, 148, 141, 130, 250, 67, 41, 232, 195, 52, 56, 118, 105, 22, 242, 184, 226, 64, 254, 162, 191, 66, 138, 20, 132, 72, 39, 221, 146, 161, 237, 86, 153, 166, 5, 120, 54, 81, 38, 77, 47, 19, 189, 4, 36, 128, 50, 111, 180, 1, 140, 13, 149, 172, 107, 181, 100, 169, 187, 83, 117, 192, 143, 139, 197, 190, 219, 136, 212, 251, 228, 231, 62, 179, 8, 60, 79, 84, 211, 144, 18, 188, 89, 35, 28, 158, 96, 30, 174, 151, 23, 112, 116, 87, 253, 127, 65, 133, 236, 220, 247, 252, 157, 55, 193, 209, 137, 196, 164, 233, 167, 16, 134, 69, 59, 98, 68, 135, 198, 223, 88, 150, 6, 142, 93, 131, 119, 108, 214, 176, 110, 183, 37]
pbox = [2, 5, 7, 4, 1, 0, 3, 6]

class  Encryptor(object):
	def  __init__(self, passphrase):
		self.key = passphrase.encode()
	
	def generateKey(self):
		self.key = hashlib.sha256(self.key).digest()[:6]
		return  self.key

	def xor(self, a, b):
		res = []
		for  ac, bc  in  zip(a, b):
		res.append(ac^bc)
		return  res

	def  encryptBlock(self, block):
		key = list(self.generateKey())
		l = list(block[:8])
		r = list(block[8:])
		for iround  in  range(6):
			keybyte = key.pop()
			for  isubround  in  range(4):
				f = []
				for  i  in  range(8):
					f.append(sbox[l[i] ^ keybyte])
					keybyte = (keybyte + 1) % 256
				f = [f[pbox[i]] for  i  in  range(8)]
				l, r = self.xor(r, f), l
		return  bytes(l+r)
		
	def  encrypt(self, plaintext):
		while  len(plaintext)%16:
		plaintext += b'\0'
		ctr = random.getrandbits(128)
		encrypted = ctr.to_bytes(16, 'big')
		for  i  in  range(0, len(plaintext), 16):
			encryptedBlock = self.encryptBlock(ctr.to_bytes(16, 'big'))
			encrypted += bytes(self.xor(plaintext[i:i+16], ctr.to_bytes(16, 'big')))
			ctr += 1
		return  encrypted

	def  parse_args():
		parser = argparse.ArgumentParser()
		parser.add_argument('file', help='file path to encrypt')
		parser.add_argument('passphrase', help='Passphrase used to encrypt file')
		parser.add_argument('-O', '--output-file', help='Specify the output file')
	return  parser.parse_args()

if  __name__ == '__main__':
	args = parse_args()
	print('Welcome to Encryptor')
	print('Encrypting %s using :' % args.file, args.passphrase)
	plaintext = open(args.file, 'rb').read()
	passphrase = args.passphrase
	ciphertext = Encryptor(passphrase).encrypt(plaintext)
	if  args.output_file:
		print("Cipher data saved in : %s" % args.output_file)
		f = open(args.output_file, 'wb')
		f.write(ciphertext)
		f.close()
	else:
		print('Your file after encryption is', ciphertext.hex())
```

Détaillons un peu le fonctionnement : 
Dans la fonction `encrypt`, on ajoute au plaintext des octets égaux à `\x0` pour que le nombre d'octets dans le plaintext soit divisible par bloque de 16 octets.
On génère ensuite un entier aléatoire de 128 bits que l'on convertit en format binaire, sur 16 octets et en big-endian.
On entre ensuite dans une boucle avec autant d'itération que de nombre de blocs de 16 octets dans le plaintext. A chaque itération, 3 choses se passent :

 1. on calcul un bloc de chiffrement à partir de l'entier aléatoire
 2. on ajoute à la variable `encrypted` le résultat de l'opération binaire XOR entre un bloc de 16 octets du plaintext et l'entier aléatoire sur 16 octets précédemment généré
 3. on incrémente l'entier aléatoire de 1

On se rend alors compte que le bloc de chiffrement n'est jamais utilisé. Il est seulement calculé. On peut donc simplifier l'algorithme en supprimant tout ce que cela implique. Il n'y a plus besoin de la fonction `encryptBlock`, donc plus besoin de clef pour déchiffrer le message. La seule chose dont nous avons besoin est de l'entier généré de manière aléatoire à chaque chiffrement d'un message.

Relisons la fonction `encrypt`. Avant la boucle `for`, nous avons une variable `encrypted` qui contient l'entier aléatoire généré, en format binaire sur 16 octets en big endian. La boucle `for`simplifié suite à nos observations sur l’utilité de `encryptBlock` est donc :
```python
for  i  in  range(0, len(plaintext), 16):
	# encryptedBlock = self.encryptBlock(ctr.to_bytes(16, 'big')) # INUTIL
	encrypted += bytes(self.xor(plaintext[i:i+16], ctr.to_bytes(16, 'big')))
	ctr += 1
```
A chaque itération, on ajoute à la suite de `encrypted` le résultat du XOR et on augmente l'entier de 1. La variable `encrypted` contient donc l'entier utilisé comme base du chiffrement ainsi que la totalité du ciphertext, ajouté par bloc de 16 octets à chaque itération les uns à la suite des autres.
Nous avons donc tout ce dont nous avons besoin pour déchiffrer le message

## Programme de déchiffrement
L'opération de chiffrement est un XOR entre un entier sur 16 octets et un bloc du plaintext sur 16 octets. Pour reverse une opération XOR, on utilise XOR, c'est a dire : 
`a XOR b = c` et `b XOR a = c`
donc 
`a = c XOR b` et `a = b XOR c`
ou bien
`b = c XOR a` et `b = a XOR c`
```python
def xor(self, a, b):
	res = []
	for  ac, bc  in  zip(a, b):
	res.append(ac^bc)
	return  res

full_text = open('CONFIDENTIEL.xlsx.enc', 'rb').read()

# Récupération du random au début du message
random_generated_bytes = full_text[:16]
# Conversion en integer
rnd_gen_int = int.from_bytes(random_generated_bytes,'big')

# Récupération du ciphertext 
ciphertext = full_text[16:]

# Initialisation du plaintext
plaintext = b''

# Dechiffrement
for i in range(0, len(ciphertext), 16):
	plaintext += bytes(xor(ciphertext[i:i+16], rnd_gen_int.to_bytes(16, 'big')))
	rnd_gen_int += 1

# Export du plaintext dans un document
out_file = open('CONFIDENTIEL.xlsx','wb')
out_file.write(plaintext)
out_file.close()
```

Il ne reste plus qu'à ouvrir le fichier avec un tableur et le flag apparait ! 
