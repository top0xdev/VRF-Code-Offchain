import eth_utils
import ecpy
from ecpy import curves
import numpy as np
import web3
#=========

cv = curves.Curve.get_curve('secp256k1')

order = cv.order
fieldSize = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

def numberToUint256(number):
	uint256 = hex(number).split('x')[1]
	return '0x'+'0'*(64 - len(uint256)) + uint256
def ptToArrNat(pt):
	return [pt.x, pt.y]
def hashToCurve(pk, seed):
    #assumes the pubkey is a valid secp256k1 pt
    domsep = numberToUint256(1) #uint256 of 1 to account for the domain separator in chlink solidity contract
    h = int.from_bytes(eth_utils.keccak(hexstr = domsep+numberToUint256(pk.x)[2:]+numberToUint256(pk.y)[2:]+numberToUint256(seed)[2:]), 'big')
    while True:
        try:
            y2 = ((h*(h*h)%fieldSize)%fieldSize+7)%fieldSize
            #n % 4 = 3 => Legendre's formula for square root holds
            #x = sqrt(a) => x = +- a^((n+1)/4)
            #see Hardy, G. H.; Wright, E. M. (1980), An Introduction to the Theory of Numbers
            y = pow(y2, (fieldSize+1)//4, fieldSize)
            pt = curves.Point(h, y, cv)
            return pt if y % 2 == 0 else -pt
        except Exception as e:    
            print(str(e.value))
            #recursively hash
            h = int.from_bytes(eth_utils.keccak(hexstr = numberToUint256(h)), 'big')

def ptToAddress(pt):
	return '0x' + \
					eth_utils.keccak(pt.x.to_bytes(32, byteorder='big') + \
					pt.y.to_bytes(32, byteorder='big'))[-20:].hex()

def marshalPoint(pt):
	return pt.x.to_bytes(32, 'big') + pt.y.to_bytes(32, 'big')

def hashMuchToScalar(h, pubk, gamma, uw, v):
	ds = 2
	return web3.Web3.solidity_keccak(
		['uint256', 'uint256[2]', 'uint256[2]', 'uint256[2]', 'uint256[2]', 'address'],
		[
			ds,
			ptToArrNat(h),
			ptToArrNat(pubk),
			ptToArrNat(gamma),
			ptToArrNat(v),
			web3.Web3.to_checksum_address(uw)
		])

def genProofWithNonce(seed, nonce, privkey):
	pkh = int.from_bytes(eth_utils.keccak(primitive=privkey), 'big')
	pubkey = cv.mul_point(pkh, cv.generator)
	h = hashToCurve(pubkey, seed)
	gamma = cv.mul_point(pkh, h)
	u = cv.mul_point(nonce, cv.generator)
	witness = ptToAddress(u)
	v = cv.mul_point(nonce, h)
	c = int(hashMuchToScalar(
	h, pubkey, gamma, witness, v
	).hex(), 16)
	s = (nonce - c*pkh)%cv.order
	outputHash = '0x'+eth_utils.keccak(hexstr =
	numberToUint256(3)+marshalPoint(gamma).hex()
	).hex()
	return {
	'pubkey': pubkey,
	'gamma': gamma,
	'c': c,
	's': s,
	'seed': seed,
	'output': outputHash
	}
def PROJECTIVE_MULTIPLICATION(x1,z1,x2,z2):
	return x1*x2, z1*z2
def PROJECTIVE_SUBTRACTION(x1,z1,x2,z2):
	p1 = z2*x1
	p2 = -x2*z1
	return (p1+p2)%fieldSize, (z1*z2)%fieldSize
def PROJECTIVE_ECCADDITION(pt1, pt2): 
	x1,y1 = pt1.x, pt1.y
	x2,y2 = pt2.x, pt2.y
	z1,z2 = 1,1
	lx, lz = y2-y1, x2-x1
	sx, dx = PROJECTIVE_MULTIPLICATION(lx, lz, lx, lz)
	sx, dx = PROJECTIVE_SUBTRACTION(sx, dx, x1, z1)
	sx, dx = PROJECTIVE_SUBTRACTION(sx, dx, x2, z2)
	sy, dy = PROJECTIVE_SUBTRACTION(x1, z1, sx, dx)
	sy, dy = PROJECTIVE_MULTIPLICATION(sy, dy, lx, lz)
	sy, dy = PROJECTIVE_SUBTRACTION(sy, dy, y1, z1)
	if dx!=dy:
		sx*=dy
		sy*=dx
		sz=dx*dy
	else:
		sz = dx
	return sx%fieldSize, sy%fieldSize, sz%fieldSize
def modinvPRIME(a, ord):
	return pow(a, ord-2, ord)
def solProofAsInChlink(seed, nonce, privkey): 
	proof = genProofWithNonce(seed, nonce, privkey)
	#reconstruct u
	u = cv.add_point(cv.mul_point(proof['c'], proof['pubkey']), cv.mul_point(proof['s'], cv.generator))
	hash = hashToCurve(proof['pubkey'], proof['seed'])
	cgw = cv.mul_point(proof['c'], proof['gamma'])
	shw = cv.mul_point(proof['s'], hash)
	_, *, PROJDENOM = PROJECTIVE_ECCADDITION(cgw, shw)
	zinv = modinvPRIME(PROJDENOM, fieldSize)
	print(
	(zinv*PROJDENOM)%fieldSize
	)
	return {
	'proof': proof,
	'uw': ptToAddress(u),
	'cgw': cgw,
	'shw': shw,
	'zinv': zinv
	}
def formatProofAsProof(proof):
	return [
	ptToArrNat(proof['proof']['pubkey']),
	ptToArrNat(proof['proof']['gamma']),
	proof['proof']['c'],
	proof['proof']['s'],
	proof['proof']['seed'],
	web3.Web3.to_checksum_address(proof['uw']),
	ptToArrNat(proof['cgw']),
	ptToArrNat(proof['shw']),
	proof['zinv']
	]
sepoliaProvider = web3.Web3(web3.HTTPProvider('[https://sepolia.gateway.tenderly.co](https://sepolia.gateway.tenderly.co/)'))
sepoliaProvider.is_connected()
abi = '[{"inputs":[{"components":[{"internalType":"uint256[2]","name":"pk","type":"uint256[2]"},{"internalType":"uint256[2]","name":"gamma","type":"uint256[2]"},{"internalType":"uint256","name":"c","type":"uint256"},{"internalType":"uint256","name":"s","type":"uint256"},{"internalType":"uint256","name":"seed","type":"uint256"},{"internalType":"address","name":"uWitness","type":"address"},{"internalType":"uint256[2]","name":"cGammaWitness","type":"uint256[2]"},{"internalType":"uint256[2]","name":"sHashWitness","type":"uint256[2]"},{"internalType":"uint256","name":"zInv","type":"uint256"}],"internalType":"struct VRF.Proof","name":"proof","type":"tuple"},{"internalType":"uint256","name":"seed","type":"uint256"}],"name":"randomValueFromVRFProof","outputs":[{"internalType":"uint256","name":"output","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256[2]","name":"pk","type":"uint256[2]"},{"internalType":"uint256[2]","name":"gamma","type":"uint256[2]"},{"internalType":"uint256","name":"c","type":"uint256"},{"internalType":"uint256","name":"s","type":"uint256"},{"internalType":"uint256","name":"seed","type":"uint256"},{"internalType":"address","name":"uWitness","type":"address"},{"internalType":"uint256[2]","name":"cGammaWitness","type":"uint256[2]"},{"internalType":"uint256[2]","name":"sHashWitness","type":"uint256[2]"},{"internalType":"uint256","name":"zInv","type":"uint256"}],"name":"verifyVRFProof","outputs":[],"stateMutability":"view","type":"function"}]'
vrfctr = sepoliaProvider.eth.contract('0xEE52fbf97738Ae76d89f260b193f5b00d05D7401', abi = abi)
_ = formatProofAsProof(solProofAsInChlink(10, 20, 30))
vrfctr.functions.verifyVRFProof(*_).call()