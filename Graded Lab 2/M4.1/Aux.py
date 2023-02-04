from Crypto.Util import *
from Crypto.Util.number import *
#from pwn import *
#import codecs
import base64

#if __name__ == "__main__":
	
	
list_of_first_few_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009]

def brute_force_isPrime(n):
	global list_of_first_few_primes
	for p in list_of_first_few_primes:
		if (n % p) == 0:
			return False
	return True

def prime_factorization(n):
	#factorize n into prime powers, collects exponents
	global list_of_first_few_primes
	
	list_of_primes_used = []
	list_of_exponents = [] #collect exponents
	
	for p in list_of_first_few_primes:
		if p > n:
			break
		cur_exp = 0
		while (n % p) == 0:
			cur_exp += 1
			n = n // p
		if cur_exp > 0:
			list_of_exponents.append(cur_exp)
			list_of_primes_used.append(p)
	return (list_of_primes_used, list_of_exponents)
	
def find_exponents(list_of_primes):
	exponents_final = [1] * len(list_of_primes)
	
	start = 1
	limit = 8
	for e1 in range(start,limit):
		print(e1)
		for e2 in range(1,limit):
			for e3 in range(1,limit):
				for e4 in range(1, limit):
					exponents_final[0] = e1
					exponents_final[1] = e2
					exponents_final[2] = e3
					exponents_final[3] = e4
					prime_power_list = map(lambda p, e: pow(p, e), list_of_primes, exponents_final)
					phi_of_N_primed = sum(prime_power_list) #compute phi(N')
					N_primed = 1 + phi_of_N_primed
					if isPrime(N_primed, false_positive_prob=1e-323): #and brute_force_isPrime(N_primed):
						return (True, exponents_final)
	return (False, [])
					
def generate_N_primed2():
	number_of_primes_to_use = 4
	
	primes_to_use_final = [1] * number_of_primes_to_use #init it
	exponents_final = [1] * number_of_primes_to_use#init it
	phi_of_N_primed = N_primed = 0
	while True:
		for i in range(number_of_primes_to_use):
			primes_to_use_final[i] = getPrime(512)		
#		primes_to_use_final[0] = getPrime(20)
#		primes_to_use_final[1] = getPrime(20)
#		primes_to_use_final[2] = getPrime(20)
		N_primed_is_prime, exponents_final = find_exponents(primes_to_use_final)
		if N_primed_is_prime:
			return (primes_to_use_final, exponents_final)
	return "Failure"



def generate_N_primed_():
	#generate N' such that N' is prime and we know the factorization of N' - 1 = phi(N') (euler toitient)
	#N' should also be of 2048 bits, like the original RSA modulus
	#I imagine that the system of congruence quations we get (after Pohlig-Hellmann and have to apply CRT to) must contain enough information to solve for d. I think 2048 bits ro more should be sufficient.
	#In paper, mid sized primes factors should be of roughly 20 bits.
	#this gives us a pointer how big the prime factors of N' - 1 = phi(N') should be.
	number_of_primes = math.ceil(2048 / 20) + 30 #(102.4 rounded up is 103)
	prime_list = [0] * (number_of_primes + 1) #first entry is for prime 2
	exponent_list = [1] * (number_of_primes + 1) #all exponents after the first one (first prime = 2) is set to 1 #see below
	
	prime_list[0] = 2
	exponent_list[0] = 10 #hardcoded, want baby_step_giant_step to run fast
	phi_of_N_primed = 1 #product of prime (powers)
	
	temp = pow(prime_list[0], exponent_list[0]) 
	
	while True:
		for k in range(1, 20):
			print("Generating prime: " + str(k))
			exponent_list[0] = k
			phi_of_N_primed = pow(prime_list[0], exponent_list[0])
			for i in range(1, number_of_primes + 1):
				cur_prime = getPrime(20)
				phi_of_N_primed *= cur_prime
				prime_list[i] = cur_prime
			N_primed = phi_of_N_primed + 1
			if isPrime(N_primed, false_positive_prob=1e-100):
				return (prime_list, exponent_list, N_primed, phi_of_N_primed)

	
def generate_N_primed():
	#generate N' such that N' is prime and we know the factorization of N' - 1 = phi(N') (euler toitient)
	#N' should also be of 2048 bits, like the original RSA modulus
	#I imagine that the system of congruence quations we get (after Pohlig-Hellmann and have to apply CRT to) must contain enough information to solve for d. I think 2048 bits ro more should be sufficient.
	#In paper, mid sized primes factors should be of roughly 20 bits.
	#this gives us a pointer how big the prime factors of N' - 1 = phi(N') should be.
	number_of_primes = math.ceil(2048 / 20) + 10 #(102.4 rounded up + 10 is 103 + 10)
	prime_list = [0] * (number_of_primes + 1) #first entry is for prime 2
	exponent_list = [1] * (number_of_primes + 1) #all exponents after the first one (first prime = 2) is set to 1 #see below
	
	prime_list[0] = 2
	phi_of_N_primed = 1 #product of prime (powers)
	
	for i in range(1, number_of_primes):
		cur_prime = getPrime(20)
		phi_of_N_primed *= cur_prime
		prime_list[i] = cur_prime
	
	#we know that pohlig diffie hellmann performs baby step giant step algorithm, which searches from the space {0, 1, ..., p_i^e_i}, where p_i is a prime factor of N' (with the corresponding power e_i) -> set e_1 to 1 to minimize search space and save time when performingbaby step giant step algorithm
	#recall that what we aim is: N' prime and phi(N') = N' - 1 smooth, since N' is at least a 2048 number, N' is an odd prime -> N' - 1 is even -> so it contains powers of 2.
	#we have to find the power of 2, e_1, such that 2^e_1 * (product of prime factors chosen) + 1 is a prime, which we select to be the N'
	
	N_primed = 0 #init
	e_1 = 1
	pow_of_2 = 2
	#search for appropriate e_1 that satiisfies above condition
	while True:
		phi_of_N_primed *= 2
		N_primed = phi_of_N_primed + 1
		if isPrime(N_primed, false_positive_prob=1e-100):
			break
		e_1 += 1
		pow_of_2 *= 2
	#after this loop:
	#N_primed is most likely a prime
	#we know prime factorisation of phi_of_N_primed = N_primed - 1
	#hopefully, this is smooth
	exponent_list[0] = e_1
	return (prime_list, exponent_list, N_primed, phi_of_N_primed)


print(generate_N_primed_())

test = [2048, 552397, 652811, 544367, 942341, 638893, 983063, 611531, 727079, 791887, 973957, 586933, 684617, 664789, 539501, 561761, 1011719, 944621, 671369, 885869, 585413, 1034339, 616181, 985277, 668873, 748567, 895393, 977693, 814537, 780457, 990013, 984911, 868787, 681647, 557861, 1018411, 564089, 835313, 906421, 872999, 652411, 876719, 912367, 847727, 886607, 884497, 833177, 1010671, 975151, 900161, 745307, 609779, 762061, 863197, 1037081, 784939, 888247, 710189, 655883, 962779, 1043921, 907567, 828007, 930269, 661939, 904759, 691631, 883483, 727471, 592873, 657413, 719027, 862957, 542293, 683713, 881663, 909787, 969131, 553769, 690293, 686143, 873073, 534931, 580417, 971753, 972047, 700171, 810079, 716621, 664613, 846913, 673979, 738623, 752699, 799801, 641843, 772403, 834983, 1000907, 742891, 574631, 1020821, 557831, 651793]

prod = 1
for n in test:
	prod *= n
print(prod)
	
#N_primed = getPrime(200)
#phi_of_N_primed = N_primed - 1
#
#print(phi_of_N_primed)
#print(prime_factorization(phi_of_N_primed))
