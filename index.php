<?php

require_once './ecdsa.php';
require_once './base58.php';
require_once './bips/bip39/bip39.php';

/**
 *
 * @author Jan Moritz Lindemann
 */
if (!extension_loaded('gmp')) {
	throw new \Exception('GMP extension seems not to be installed');
}

//********************** */
class BitcoinTOOL
{

	private string $networkPrefix;
	private $ecdsa;

	public function __construct()
	{
		$this->ecdsa = new ECDSA();

		$this->networkPrefix = '00';
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
		$sha256d = hash('sha256', hex2bin(hash('sha256', $data)));
		return $sha256d;
	}

	/**
	 * @param string $data
	 * @return string (hexa)
	 */
	public function hash160($data)
	{
		$ripemd = hash('ripemd160', hash('sha256', $data, true));
		return $ripemd;
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
		} while (gmp_cmp(gmp_init($res, 16), gmp_sub($this->ecdsa->n, gmp_init(1, 10))) === 1); // make sure the generate string is smaller than n

		return $res;
	}

	public function getPubKey(bool $compressed = false, array $pubKeyPts = []): string
	{

		if (empty($pubKeyPts))
			$pubKeyPts = $this->ecdsa->getPubKeyPoints();

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

	public function getAddressh160(bool $compressed = false): string
	{
		$address = $this->getPubKey($compressed);

		$address =  $this->hash160(hex2bin($address));
		return $address;
	}

	public function getAddress(bool $compressed = false, bool $verify = false): string
	{
		$address = $this->getPubKey($compressed);

		$address = $this->getNetworkPrefix() . $this->hash160(hex2bin($address));

		//checksum
		$address = $address . substr($this->hash256d(hex2bin($address)), 0, 8);
		$address = Base58::encode($address);
		if ($verify == false) {
			return $address;
		}
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
		if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->ecdsa->n, gmp_init(1, 10))) === 1) {
			throw new \Exception('Private Key is not in the 1,n-1 range');
		}
		$this->ecdsa->k = $k;
	}

	public function setPrivateKeyFromSeed(string $seed): void
	{
		$k = hash('sha256', $seed);
		if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->ecdsa->n, gmp_init(1, 10))) === 1) {
			throw new \Exception('Private Key is not in the 1,n-1 range');
		}
		$this->ecdsa->k = $k;
	}

	public function setPrivateKeyFromMnemonic(string $mnemonic, string $passphrase = ''): void
	{
		$bip39 = new BIP39();
		$seed = $bip39->mnemonicToSeed($mnemonic, $passphrase);
		$masterKey = $bip39->seedToMasterKey($seed);
		$k = bin2hex($masterKey['privateKey']);
		if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->ecdsa->n, gmp_init(1, 10))) === 1) {
			throw new \Exception('Private Key is not in the 1,n-1 range');
		}
		$this->ecdsa->k = $k;
	}
	public function setPrivateKeyFromRandomMnemonic(string $passphrase = '', string $worldLanguage = 'english'): string
	{
		$entropy = BIP39::generateEntropy(256);
		$mnemonic = BIP39::entropyToMnemonic($entropy, $worldLanguage);
		$seed = BIP39::mnemonicToSeed($mnemonic, $passphrase);
		$masterKey = BIP39::seedToMasterKey($seed);
		$k = bin2hex($masterKey['privateKey']);
		if (gmp_cmp(gmp_init($k, 16), gmp_sub($this->ecdsa->n, gmp_init(1, 10))) === 1) {
			throw new \Exception('Private Key is not in the 1,n-1 range');
		}
		$this->ecdsa->k = $k;
		return $mnemonic;
	}

	public function getPrivateKey(): string
	{
		return $this->ecdsa->k;
	}

	public function getPrivateKeyDecimal(?int $divBy = null): string
	{
		$gmp = gmp_init($this->ecdsa->k, 16);
		return gmp_strval($gmp, 10);
	}


	public function generateRandomPrivateKey(string $extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d'): void
	{
		$this->ecdsa->k = $this->generateRandom256BitsHexaString($extra);
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
		if (!isset($this->ecdsa->k)) {
			throw new \Exception('No Private Key was defined');
		}

		$k = $this->ecdsa->k;

		while (strlen($k) < 64)
			$k = '0' . $k;

		$secretKey = $this->getPrivatePrefix() . $k;

		if ($compressed) {
			$secretKey .= '01';
		}

		$secretKey .= substr($this->hash256d(hex2bin($secretKey)), 0, 8);

		return Base58::encode($secretKey);
	}

	public function getBalance(?string $address = null, bool $compressed = false)
	{
		$addr = $address ?? $this->getAddress($compressed);
		try {
			$balance = file_get_contents('https://blockchain.info/q/addressbalance/' . $addr);
			return $balance;
		} catch (\Throwable $th) {
			return 'Error';
		}
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
		$hex = substr($key, 2, 64);
		$this->setPrivateKeyHex($hex);
	}
}
