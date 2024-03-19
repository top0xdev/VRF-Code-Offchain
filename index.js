const ethers = require("ethers");
const BN = require("bn.js");
const ethUtil = require("ethereumjs-util");
const EC = require("elliptic").ec;
// const keccak256 = require("js-sha3").keccak256;
const ec = new EC("secp256k1");

const cv = ec.curve;
const order = cv.n;
const fieldSize = new BN(
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
  "hex"
);

function numberToUint256(number) {
  const uint256 = BigInt(number).toString(16);
  return "0x" + "0".repeat(64 - uint256.length) + uint256;
}

function ptToArrNat(pt) {
  return [pt.getX().toString(), pt.getY().toString()];
}

function fastModularExponentiation(a, b, n) {
  let tmp = new BN(b);

  a = a.mod(n);
  var result = new BN(1);
  var x = a;

  while (tmp.cmp(new BN(0)) == 1) {
    var leastSignificantBit = tmp.mod(new BN(2));
    tmp = tmp.div(new BN(2));

    if (leastSignificantBit == new BN(1)) {
      result = result.mul(x);
      result = result.mod(n);
    }

    x = x.mul(x);
    x = x.mod(n);
  }
  return result;
}

function hashToCurve(pk, seed) {
  // Assumes the pubkey is a valid secp256k1 point
  const domSep = new BN(1); // uint256 of 1 to account for the domain separator in chlink solidity contract
  const tmpSeed = new BN(seed);
  let h = new BN(
    ethUtil.keccak256(
      Buffer.concat([
        domSep.toBuffer(),
        pk.x.toBuffer(),
        pk.y.toBuffer(),
        tmpSeed.toBuffer(),
      ])
    ),
    16
  );
  console.log("Entered the loop");
  while (true) {
    try {
      let y2 = h
        .mul(h.pow(new BN(2)))
        .mod(fieldSize)
        .mod(fieldSize)
        .add(new BN(7))
        .mod(fieldSize);
      // n % 4 = 3 => Legendre's formula for square root holds
      // x = sqrt(a) => x = +- a^((n+1)/4)
      // See Hardy, G. H.; Wright, E. M. (1980), An Introduction to the Theory of Numbers
      // let y = y2.pow(fieldSize.add(new BN(1)).div(new BN(4))).mod(fieldSize);
      let y = fastModularExponentiation(
        y2,
        fieldSize.add(new BN(1)).div(new BN(4)),
        fieldSize
      );
      let pt = ec.curve.point(h, y);
      // console.log()
      console.log("trying to return pt");
      return pt.y.mod(new BN(2)).eq(new BN(0)) ? pt : pt.neg();
    } catch (e) {
      console.log("Entered error catch");
      console.log(e);
      // Recursively hash
      h = new BN(ethUtil.keccak256(h.toBuffer()), 16);
    }
  }
}

function ptToAddress(pt) {
  return (
    "0x" +
    ethers.utils
      .keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ["uint256", "uint256"],
          [pt.getX().toString(), pt.getY().toString()]
        )
      )
      .slice(-40)
  );
}

function toBytes(number, length, byteOrder = "big") {
  const byteArray = new Array(length).fill(0);
  for (let index = 0; index < length; index++) {
    const byteIndex = byteOrder === "big" ? length - index - 1 : index;
    byteArray[byteIndex] = number & 0xff;
    number = number >> 8;
  }
  return byteArray;
}

function marshalPoint(pt) {
  //console.log(pt.getX().toString('hex'));
  // console.log(ethers.utils.hexValue(pt.getX().toString())); //still wrangling this here
  // console.log(ethers.utils.hexValue(pt.x.toString()), pt.y);
  // const tmp = new BN(pt.x);
  // console.log(ethers.utils.hexlify(pt.x.toString(16)));
  // return (
  //   ethers.utils.arrayify(
  //     // ethers.utils.hexlify(ethers.utils.hexValue(pt.y.toString()))
  //     // ethers.utils.hexlify(pt.x.toString(16))
  //   ) +
  //   ethers.utils.arrayify(
  //     // ethers.utils.hexlify(ethers.utils.hexValue(pt.x.toString()))
  //     ethers.utils.hexlify(pt.y)
  //   )
  // );
  const a = toBytes(pt.x, 32);
  const b = toBytes(pt.y, 32);
  console.log(a, b);
  return a + b;
}

function hashMuchToScalar(h, pubk, gamma, uw, v) {
  const ds = 2; // chlink domain separator
  return ethers.utils.keccak256(
    ethers.utils.defaultAbiCoder.encode(
      [
        "uint256",
        "uint256[2]",
        "uint256[2]",
        "uint256[2]",
        "uint256[2]",
        "address",
      ],
      [
        ds,
        ptToArrNat(h),
        ptToArrNat(pubk),
        ptToArrNat(gamma),
        ptToArrNat(v),
        uw,
      ]
    )
  );
}

function genProofWithNonce(seed, nonce, privkey) {
  const pubkey = ec.keyFromPrivate(privkey).getPublic();
  const pubkeyBytes = pubkey.encode("array");
  const pkh = ethUtil.keccak256(Buffer(pubkeyBytes));

  // Assuming hashToCurve, cv.mul_point, ptToAddress, hashMuchToScalar, and marshalPoint are defined elsewhere
  // and have been adapted to JavaScript. For the sake of this example, let's assume they are placeholders.
  const h = hashToCurve(pubkey, seed);
  console.log("hashed curve");
  const point = cv.pointFromX(pkh, true);
  console.log("point genned");
  console.log(cv.g);
  const gamma = h.mul(pkh);
  console.log("gamma");
  const u = cv.pointFromX(nonce, true);
  console.log("u");
  console.log(u.getX().toString());
  console.log(Object.getOwnPropertyNames(u));
  // const u = cv.mul_point(nonce, cv.generator);
  const witness = ptToAddress(u);
  // const v = cv.mul_point(nonce, h);
  point2 = cv.pointFromX(nonce, true); //fail to see what for. Isn't this just a copy of u?
  const v = h.mul(nonce);
  const c = parseInt(
    hashMuchToScalar(h, pubkey, gamma, witness, v).toString("hex"),
    16
  );
  const s = (nonce - c * pkh) % cv.order;
  console.log("beforehash");
  console.log(marshalPoint(gamma));
  const outputHash =
    "0x" +
    ethUtil
      .keccak256(
        Buffer.concat([
          numberToUint256(3),
          Buffer.from(marshalPoint(gamma).toString("hex"), "hex"),
        ])
      )
      .toString("hex");
  console.log("hashed");

  return {
    pubkey: pubkey,
    gamma: gamma,
    c: c,
    s: s,
    seed: seed,
    output: outputHash,
  };
}

function PROJECTIVE_MULTIPLICATION(x1, z1, x2, z2) {
  return [x1 * x2, z1 * z2];
}

function PROJECTIVE_SUBTRACTION(x1, z1, x2, z2) {
  const p1 = z2 * x1;
  const p2 = -x2 * z1;
  return [(p1 + p2) % fieldSize, (z1 * z2) % fieldSize];
}

function PROJECTIVE_ECCADDITION(pt1, pt2) {
  const [x1, y1] = [pt1.x, pt1.y];
  const [x2, y2] = [pt2.x, pt2.y];
  const [z1, z2] = [1, 1];
  const [lx, lz] = [y2 - y1, x2 - x1];
  let [sx, dx] = PROJECTIVE_MULTIPLICATION(lx, lz, lx, lz);
  [sx, dx] = PROJECTIVE_SUBTRACTION(sx, dx, x1, z1);
  [sx, dx] = PROJECTIVE_SUBTRACTION(sx, dx, x2, z2);
  let [sy, dy] = PROJECTIVE_SUBTRACTION(x1, z1, sx, dx);
  [sy, dy] = PROJECTIVE_MULTIPLICATION(sy, dy, lx, lz);
  [sy, dy] = PROJECTIVE_SUBTRACTION(sy, dy, y1, z1);
  let sz;
  if (dx !== dy) {
    sx *= dy;
    sy *= dx;
    sz = dx * dy;
  } else {
    sz = dx;
  }
  return [sx % fieldSize, sy % fieldSize, sz % fieldSize];
}

function modinvPRIME(a, ord) {
  return BigInt(Math.pow(a, ord - 2)) % ord;
}

function solProofAsInChlink(seed, nonce, privkey) {
  const proof = genProofWithNonce(seed, nonce, privkey);
  const u = cv.add_point(
    cv.mul_point(proof["c"], proof["pubkey"]),
    cv.mul_point(proof["s"], cv.g)
  );
  const hash = hashToCurve(proof["pubkey"], proof["seed"]);
  const cgw = cv.mul_point(proof["c"], proof["gamma"]);
  const shw = cv.mul_point(proof["s"], hash);
  const [_, ...PROJDENOM] = PROJECTIVE_ECCADDITION(cgw, shw);
  const zinv = modinvPRIME(PROJDENOM, fieldSize);
  console.log((zinv * PROJDENOM) % fieldSize);
  return {
    proof: proof,
    uw: ptToAddress(u),
    cgw: cgw,
    shw: shw,
    zinv: zinv,
  };
}

function formatProofAsProof(proof) {
  return [
    ptToArrNat(proof["proof"]["pubkey"]),
    ptToArrNat(proof["proof"]["gamma"]),
    proof["proof"]["c"],
    proof["proof"]["s"],
    proof["proof"]["seed"],
    ethers.utils.getAddress(proof["uw"]),
    ptToArrNat(proof["cgw"]),
    ptToArrNat(proof["shw"]),
    proof["zinv"],
  ];
}

const sepoliaProvider = new ethers.providers.JsonRpcProvider(
  "https://sepolia.gateway.tenderly.co/"
);
sepoliaProvider.detectNetwork().then(() => console.log("Connected to Sepolia"));

const abi =
  '[{"inputs":[{"components":[{"internalType":"uint256[2]","name":"pk","type":"uint256[2]"},{"internalType":"uint256[2]","name":"gamma","type":"uint256[2]"},{"internalType":"uint256","name":"c","type":"uint256"},{"internalType":"uint256","name":"s","type":"uint256"},{"internalType":"uint256","name":"seed","type":"uint256"},{"internalType":"address","name":"uWitness","type":"address"},{"internalType":"uint256[2]","name":"cGammaWitness","type":"uint256[2]"},{"internalType":"uint256[2]","name":"sHashWitness","type":"uint256[2]"},{"internalType":"uint256","name":"zInv","type":"uint256"}],"internalType":"struct VRF.Proof","name":"proof","type":"tuple"},{"internalType":"uint256","name":"seed","type":"uint256"}],"name":"randomValueFromVRFProof","outputs":[{"internalType":"uint256","name":"output","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256[2]","name":"pk","type":"uint256[2]"},{"internalType":"uint256[2]","name":"gamma","type":"uint256[2]"},{"internalType":"uint256","name":"c","type":"uint256"},{"internalType":"uint256","name":"s","type":"uint256"},{"internalType":"uint256","name":"seed","type":"uint256"},{"internalType":"address","name":"uWitness","type":"address"},{"internalType":"uint256[2]","name":"cGammaWitness","type":"uint256[2]"},{"internalType":"uint256[2]","name":"sHashWitness","type":"uint256[2]"},{"internalType":"uint256","name":"zInv","type":"uint256"}],"name":"verifyVRFProof","outputs":[],"stateMutability":"view","type":"function"}]';

const vrfctr = new ethers.Contract(
  "0xEE52fbf97738Ae76d89f260b193f5b00d05D7401",
  abi,
  sepoliaProvider
);
const proof = solProofAsInChlink(10, 20, 30);
const formattedProof = formatProofAsProof(proof);
console.log(formattedProof);
vrfctr.functions
  .verifyVRFProof(...formattedProof)
  .call()
  .then((result) => console.log(result));
