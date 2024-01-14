<?php
/**
 *
 * @author Jan Moritz Lindemann
 */
if (!extension_loaded('gmp')) {
	throw new \Exception('GMP extension seems not to be installed');
}


class Base58
{
	/***
	 * encode a hexadecimal string in Base58.
	 *
	 * @param string $data (hexa)
	 * @param bool $littleEndian
	 * @return string (base58)
	 * @throws \Exception
	 */
	static public function encode($data, $littleEndian = true): string
	{
		$res = '';
		$dataIntVal = gmp_init($data, 16);
		while (gmp_cmp($dataIntVal, gmp_init(0, 10)) > 0) {
			$qr = gmp_div_qr($dataIntVal, gmp_init(58, 10));
			$dataIntVal = $qr[0];
			$reminder = gmp_strval($qr[1]);
			if (!Base58::permutation($reminder)) {
				throw new \Exception('Something went wrong during base58 encoding');
			}
			$res .= Base58::permutation($reminder);
		}

		//get number of leading zeros
		$leading = '';
		$i = 0;
		while (substr($data, $i, 1) === '0') {
			if ($i !== 0 && $i % 2) {
				$leading .= '1';
			}
			$i++;
		}

		if ($littleEndian)
			return strrev($res . $leading);
		else
			return $res . $leading;
	}

	/***
	 * Decode a Base58 encoded string and returns it's value as a hexadecimal string
	 *
	 * @param string $encodedData (base58)
	 * @param bool $littleEndian
	 * @return string (hexa)
	 */
	static public function decode($encodedData, $littleEndian = true): string
	{
		$res = gmp_init(0, 10);
		$length = strlen($encodedData);
		if ($littleEndian) {
			$encodedData = strrev($encodedData);
		}

		for ($i = $length - 1; $i >= 0; $i--) {
			$res = gmp_add(
				gmp_mul(
					$res,
					gmp_init(58, 10)
				),
				Base58::permutation(substr($encodedData, $i, 1), true)
			);
		}

		$res = gmp_strval($res, 16);
		$i = $length - 1;
		while (substr($encodedData, $i, 1) === '1') {
			$res = '00' . $res;
			$i--;
		}

		if (strlen($res) % 2 !== 0) {
			$res = '0' . $res;
		}

		return $res;
	}

	/***
	 * Permutation table used for Base58 encoding and decoding.
	 *
	 * @param string $char
	 * @param bool $reverse
	 * @return string|null
	 */
	static public function permutation($char, $reverse = false): string
	{
		$table = [
			'1',
			'2',
			'3',
			'4',
			'5',
			'6',
			'7',
			'8',
			'9',
			'A',
			'B',
			'C',
			'D',
			'E',
			'F',
			'G',
			'H',
			'J',
			'K',
			'L',
			'M',
			'N',
			'P',
			'Q',
			'R',
			'S',
			'T',
			'U',
			'V',
			'W',
			'X',
			'Y',
			'Z',
			'a',
			'b',
			'c',
			'd',
			'e',
			'f',
			'g',
			'h',
			'i',
			'j',
			'k',
			'm',
			'n',
			'o',
			'p',
			'q',
			'r',
			's',
			't',
			'u',
			'v',
			'w',
			'x',
			'y',
			'z'
		];

		if ($reverse) {
			$reversedTable = [];
			foreach ($table as $key => $element) {
				$reversedTable[$element] = $key;
			}

			if (isset($reversedTable[$char]))
				return $reversedTable[$char];
			else
				return null;
		}

		if (isset($table[$char]))
			return $table[$char];
		else
			return null;
	}
}
class BitcoinECDSA
{

	private $k;
	private $a;
	private $b;
	private $p;
	private $n;
	private $G;
	private string $networkPrefix;

	public function __construct()
	{
		$this->a = gmp_init('0', 10);
		$this->b = gmp_init('7', 10);
		$this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
		$this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

		$this->G = [
			'x' => gmp_init('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
			'y' => gmp_init('32670510020758816978083085130507043184471273380659243275938904335757337482424')
		];

		$this->networkPrefix = '00';
	}

	/***
	 * Convert a number to a compact Int
	 * taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/verifymessage.php
	 *
	 * @param int $i
	 * @return string (bin)
	 * @throws \Exception
	 */
	private function numToVarIntString($i)
	{
		if ($i < 0xfd) {
			return chr($i);
		} else if ($i <= 0xffff) {
			return pack('Cv', 0xfd, $i);
		} else if ($i <= 0xffffffff) {
			return pack('CV', 0xfe, $i);
		} else {
			throw new \Exception('int too large');
		}
	}

	/***
	 * Set the network prefix, '00' = main network, '6f' = test network.
	 *
	 * @param string $prefix (hexa)
	 */
	public function setNetworkPrefix($prefix)
	{
		$this->networkPrefix = $prefix;
	}

	/**
	 * Returns the current network prefix, '00' = main network, '6f' = test network.
	 *
	 * @return string (hexa)
	 */
	public function getNetworkPrefix()
	{
		return $this->networkPrefix;
	}

	/**
	 * Returns the current network prefix for WIF, '80' = main network, 'ef' = test network.
	 *
	 * @return string (hexa)
	 */
	public function getPrivatePrefix()
	{
		if ($this->networkPrefix == '6f')
			return 'ef';
		else
			return '80';
	}



	/***
	 * Bitcoin standard 256 bit hash function : double sha256
	 *
	 * @param string $data
	 * @return string (hexa)
	 */
	public function hash256d($data)
	{
		return hash('sha256', hex2bin(hash('sha256', $data)));
	}

	/**
	 * @param string $data
	 * @return string (hexa)
	 */
	public function hash160($data)
	{
		return hash('ripemd160', hex2bin(hash('sha256', $data)));
	}

	/**
	 * Generates a random 256 bytes hexadecimal encoded string that is smaller than n
	 *
	 * @param string $extra
	 * @return string (hexa)
	 * @throws \Exception
	 */
	public function generateRandom256BitsHexaString($extra = 'FkejkzqesrfeifH3ioio9hb55sdssdsdfOO:ss')
	{
		do {
			$bytes = openssl_random_pseudo_bytes(256, $cStrong);
			$hex = bin2hex($bytes);
			$random = $hex . microtime(true) . $extra;

			if ($cStrong === false) {
				throw new \Exception('Your system is not able to generate strong enough random numbers');
			}
			$res = $this->hash256d($random);

		} while (gmp_cmp(gmp_init($res, 16), gmp_sub($this->n, gmp_init(1, 10))) === 1); // make sure the generate string is smaller than n

		return $res;
	}



	/***
	 * Computes the result of a point addition and returns the resulting point as an Array.
	 *
	 * @param Array $pt
	 * @return Array Point
	 * @throws \Exception
	 */
	private function doublePoint(array $pt)
	{
		$a = $this->a;
		$p = $this->p;

		$gcd = gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p), $p));
		if ($gcd !== '1') {
			throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
		}

		// SLOPE = (3 * ptX^2 + a )/( 2*ptY )
		// Equals (3 * ptX^2 + a ) * ( 2*ptY )^-1
		$slope = gmp_mod(
			gmp_mul(
				gmp_invert(
					gmp_mod(
						gmp_mul(
							gmp_init(2, 10),
							$pt['y']
						),
						$p
					),
					$p
				),
				gmp_add(
					gmp_mul(
						gmp_init(3, 10),
						gmp_pow($pt['x'], 2)
					),
					$a
				)
			),
			$p
		);

		// nPtX = slope^2 - 2 * ptX
		// Equals slope^2 - ptX - ptX
		$nPt = [];
		$nPt['x'] = gmp_mod(
			gmp_sub(
				gmp_sub(
					gmp_pow($slope, 2),
					$pt['x']
				),
				$pt['x']
			),
			$p
		);

		// nPtY = slope * (ptX - nPtx) - ptY
		$nPt['y'] = gmp_mod(
			gmp_sub(
				gmp_mul(
					$slope,
					gmp_sub(
						$pt['x'],
						$nPt['x']
					)
				),
				$pt['y']
			),
			$p
		);

		return $nPt;
	}

	/***
	 * Computes the result of a point addition and returns the resulting point as an Array.
	 *
	 * @param Array $pt1
	 * @param Array $pt2
	 * @return Array Point
	 * @throws \Exception
	 */
	private function addPoints(array $pt1, array $pt2)
	{
		$p = $this->p;
		if (gmp_cmp($pt1['x'], $pt2['x']) === 0 && gmp_cmp($pt1['y'], $pt2['y']) === 0) //if identical
		{
			return $this->doublePoint($pt1);
		}

		$gcd = gmp_strval(gmp_gcd(gmp_sub($pt1['x'], $pt2['x']), $p));
		if ($gcd !== '1') {
			throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
		}

		// SLOPE = (pt1Y - pt2Y)/( pt1X - pt2X )
		// Equals (pt1Y - pt2Y) * ( pt1X - pt2X )^-1
		$slope = gmp_mod(
			gmp_mul(
				gmp_sub(
					$pt1['y'],
					$pt2['y']
				),
				gmp_invert(
					gmp_sub(
						$pt1['x'],
						$pt2['x']
					),
					$p
				)
			),
			$p
		);

		// nPtX = slope^2 - ptX1 - ptX2
		$nPt = [];
		$nPt['x'] = gmp_mod(
			gmp_sub(
				gmp_sub(
					gmp_pow($slope, 2),
					$pt1['x']
				),
				$pt2['x']
			),
			$p
		);

		// nPtY = slope * (ptX1 - nPtX) - ptY1
		$nPt['y'] = gmp_mod(
			gmp_sub(
				gmp_mul(
					$slope,
					gmp_sub(
						$pt1['x'],
						$nPt['x']
					)
				),
				$pt1['y']
			),
			$p
		);

		return $nPt;
	}

	/***
	 * Computes the result of a point multiplication and returns the resulting point as an Array.
	 *
	 * @param string|resource $k (hexa|GMP|Other bases definded in base)
	 * @param Array $pG
	 * @param $base
	 * @throws \Exception
	 * @return Array Point
	 */
	private function mulPoint($k, array $pG, $base = null)
	{
		//in order to calculate k*G
		if ($base === 16 || $base === null || is_resource($base))
			$k = gmp_init($k, 16);
		if ($base === 10)
			$k = gmp_init($k, 10);
		$kBin = gmp_strval($k, 2);

		$lastPoint = $pG;
		for ($i = 1; $i < strlen($kBin); $i++) {
			if (substr($kBin, $i, 1) === '1') {
				$dPt = $this->doublePoint($lastPoint);
				$lastPoint = $this->addPoints($dPt, $pG);
			} else {
				$lastPoint = $this->doublePoint($lastPoint);
			}
		}
		if (!$this->validatePoint(gmp_strval($lastPoint['x'], 16), gmp_strval($lastPoint['y'], 16)))
			throw new \Exception('The resulting point is not on the curve.');
		return $lastPoint;
	}

	/***
	 * Calculates the square root of $a mod p and returns the 2 solutions as an array.
	 */
	private function sqrt($a): array|null
	{
		$p = $this->p;

		if (gmp_legendre($a, $p) !== 1) {
			//no result
			return null;
		}

		if (gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) === '3') {
			$sqrt1 = gmp_powm(
				$a,
				gmp_div_q(
					gmp_add($p, gmp_init(1, 10)),
					gmp_init(4, 10)
				),
				$p
			);
			// there are always 2 results for a square root
			// In an infinite number field you have -2^2 = 2^2 = 4
			// In a finite number field you have a^2 = (p-a)^2
			$sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);
			return [$sqrt1, $sqrt2];
		} else {
			throw new \Exception('P % 4 != 3 , this isn\'t supported yet.');
		}
	}


	private function calculateYWithX(string $x, $derEvenOrOddCode = null): array|null|string
	{
		$a = $this->a;
		$b = $this->b;
		$p = $this->p;

		$x = gmp_init($x, 16);
		$y2 = gmp_mod(
			gmp_add(
				gmp_add(
					gmp_powm($x, gmp_init(3, 10), $p),
					gmp_mul($a, $x)
				),
				$b
			),
			$p
		);

		$y = $this->sqrt($y2);

		if ($y === null) //if there is no result
		{
			return null;
		}

		if ($derEvenOrOddCode === null) {
			return $y;
		} else if ($derEvenOrOddCode === '02') // even
		{
			$resY = null;
			if (gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10) === '0')
				$resY = gmp_strval($y[0], 16);
			if (gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10) === '0')
				$resY = gmp_strval($y[1], 16);
			if ($resY !== null) {
				while (strlen($resY) < 64) {
					$resY = '0' . $resY;
				}
			}
			return $resY;
		} else if ($derEvenOrOddCode === '03') // odd
		{
			$resY = null;
			if (gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10) === '1')
				$resY = gmp_strval($y[0], 16);
			if (gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10) === '1')
				$resY = gmp_strval($y[1], 16);
			if ($resY !== null) {
				while (strlen($resY) < 64) {
					$resY = '0' . $resY;
				}
			}
			return $resY;
		}

		return null;
	}

	private function validatePoint(string $x, string $y): bool
	{
		$a = $this->a;
		$b = $this->b;
		$p = $this->p;

		$x = gmp_init($x, 16);
		$y2 = gmp_mod(
			gmp_add(
				gmp_add(
					gmp_powm($x, gmp_init(3, 10), $p),
					gmp_mul($a, $x)
				),
				$b
			),
			$p
		);
		$y = gmp_mod(gmp_pow(gmp_init($y, 16), 2), $p);

		if (gmp_cmp($y2, $y) === 0)
			return true;
		else
			return false;
	}

	/***
	 * returns the X and Y point coordinates of the private key.
	 *
	 * @return Array Point
	 * @throws \Exception
	 */
	private function getPubKeyPoints(): array
	{
		$G = $this->G;
		$k = $this->k;

		if (!isset($this->k)) {
			throw new \Exception('No Private Key was defined');
		}

		$pubKey = $this->mulPoint(
			$k,
			['x' => $G['x'], 'y' => $G['y']]
		);

		$pubKey['x'] = gmp_strval($pubKey['x'], 16);
		$pubKey['y'] = gmp_strval($pubKey['y'], 16);

		while (strlen($pubKey['x']) < 64) {
			$pubKey['x'] = '0' . $pubKey['x'];
		}

		while (strlen($pubKey['y']) < 64) {
			$pubKey['y'] = '0' . $pubKey['y'];
		}

		return $pubKey;
	}

	public function getPubKey(bool $compressed = false, array $pubKeyPts = []): string
	{

		if (empty($pubKeyPts))
			$pubKeyPts = $this->getPubKeyPoints();

		if ($compressed == false) {
			$uncompressedPubKey = '04' . $pubKeyPts['x'] . $pubKeyPts['y'];

			return $uncompressedPubKey;
		}

		if (gmp_strval(gmp_mod(gmp_init($pubKeyPts['y'], 16), gmp_init(2, 10))) === '0')
			$compressedPubKey = '02' . $pubKeyPts['x'];	//if $pubKey['y'] is even
		else
			$compressedPubKey = '03' . $pubKeyPts['x'];	//if $pubKey['y'] is odd

		return $compressedPubKey;
	}

	public function getAddressFromPublicHex(string $publicKeyHex, string $networkPrefix = '00'): string
	{
		$address = $this->getNetworkPrefix() . $this->hash160(hex2bin($publicKeyHex));

		//checksum
		$address = $address . substr($this->hash256d(hex2bin($address)), 0, 8);
		$address = Base58::encode($address);

		if ($this->validateAddress($address))
			return $address;
		else
			throw new \Exception('the generated address seems not to be valid.');

	}

	public function getAddress(bool $compressed = false): string
	{
		$address = $this->getPubKey($compressed);

		$address = $this->getNetworkPrefix() . $this->hash160(hex2bin($address));

		//checksum
		$address = $address . substr($this->hash256d(hex2bin($address)), 0, 8);
		$address = Base58::encode($address);

		if ($this->validateAddress($address))
			return $address;
		else
			throw new \Exception('the generated address seems not to be valid.');
	}

	public function getP2SHAddress(bool $compressed = false): string
	{

		$pubkey = $this->getPubKey($compressed);

		$keyhash = '00' . '14' . $this->hash160(hex2bin($pubkey));
		$address = '05' . $this->hash160(hex2bin($keyhash));

		$checksum = $this->hash256d(hex2bin($address));
		$address = $address . substr($checksum, 0, 8);

		$address = Base58::encode($address);

		if ($this->validateAddress($address))
			return $address;
		else
			throw new \Exception('the generated address seems not to be valid.');
	}

	public function setPrivateKeyHex(string $k): void
	{
		//private key has to be passed as an hexadecimal number
		if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->n, gmp_init(1, 10))) === 1) {
			throw new \Exception('Private Key is not in the 1,n-1 range');
		}
		$this->k = $k;
	}

	public function setPrivateKeyFromSeed(string $seed): void
	{
		$k = hash('sha256', $seed);
		if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->n, gmp_init(1, 10))) === 1) {
			throw new \Exception('Private Key is not in the 1,n-1 range');
		}
		$this->k = $k;
	}

	public function getPrivateKey(): string
	{
		return $this->k;
	}


	public function generateRandomPrivateKey(string $extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d'): void
	{
		$this->k = $this->generateRandom256BitsHexaString($extra);
	}

	public function validateAddress(string $address): bool
	{
		$address = hex2bin(Base58::decode($address));
		if (strlen($address) !== 25)
			return false;
		$checksum = substr($address, 21, 4);
		$rawAddress = substr($address, 0, 21);

		if (substr(hex2bin($this->hash256d($rawAddress)), 0, 4) === $checksum)
			return true;
		else
			return false;
	}

	public function getWif(bool $compressed = false): string
	{
		if (!isset($this->k)) {
			throw new \Exception('No Private Key was defined');
		}

		$k = $this->k;

		while (strlen($k) < 64)
			$k = '0' . $k;

		$secretKey = $this->getPrivatePrefix() . $k;

		if ($compressed) {
			$secretKey .= '01';
		}

		$secretKey .= substr($this->hash256d(hex2bin($secretKey)), 0, 8);

		return Base58::encode($secretKey);
	}

	public function validateWifKey(string $wif): bool
	{
		$key = Base58::decode($wif, true);
		$length = strlen($key);
		$checksum = $this->hash256d(hex2bin(substr($key, 0, $length - 8)));
		if (substr($checksum, 0, 8) === substr($key, $length - 8, 8))
			return true;
		else
			return false;
	}

	public function setPrivateKeyWithWif(string $wif): void
	{
		if (!$this->validateWifKey($wif)) {
			throw new \Exception('Invalid WIF');
		}

		$key = Base58::decode($wif, true);

		$this->setPrivateKeyHex(substr($key, 2, 64));
	}

}




$btc = new BitcoinECDSA();
$btc->setPrivateKeyHex('00');
echo 'address: ' . $btc->getAddress() . PHP_EOL;
echo 'addressC: ' . $btc->getAddress(true) . PHP_EOL;
echo 'private key: ' . $btc->getPrivateKey() . PHP_EOL;
echo 'public key: ' . $btc->getPubKey() . PHP_EOL;
echo 'wif: ' . $btc->getWif() . PHP_EOL;
