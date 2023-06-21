<?php
error_reporting(0);
require('./vendor/autoload.php');

use Elliptic\EC;
use StephenHill\Base58;

const MAINNET_VERSION = '00';
const TESTNET_VERSION = '6f';
const REGTEST_VERSION = '6f';

class BitcoinAddress
{
	private EC $ec;
	private Base58 $base58;
	private $keyPair;
	public $phase;
	public function __construct()
	{
		$this->ec = new EC('secp256k1');
		$this->base58 = new Base58();

		$random_bytes = hash('sha256', strtoupper(bin2hex(random_bytes(32))));
		$this->keyPair = $this->ec->keyFromPrivate($random_bytes);
	}

	static public function fromPrivateKeyHex($privateKeyHex)
	{
		$obj = new BitcoinAddress();
		$obj->keyPair = self::$ec->keyFromPrivate($privateKeyHex);
		return $obj;
	}

	static public function fromSeed($seed)
	{
		$seed256Hex = hash('sha256', strtoupper(bin2hex($seed)));
		$obj = new BitcoinAddress();
		$obj->keyPair = self::$ec->keyFromPrivate($seed256Hex);
		return $obj;
	}

	public function fromSeedL($seed)
	{
		$random_bytes = hash('sha256', $seed);
		$this->keyPair = $this->ec->keyFromPrivate($random_bytes);
	}

	public function getAddress(string $version = MAINNET_VERSION)
	{
		if ($this->keyPair === null) {
			throw new Exception('keyPair is null');
		}
		$publicKey = hex2bin($this->getPublicKeyHex());
		$publicKeySHA256 = hash('sha256', $publicKey);

		$hash160 = hash('ripemd160', hex2bin($publicKeySHA256));
		$hashEBytes = $version . $hash160;

		$firstSHA = hash('sha256', hex2bin($hashEBytes));
		$secondSHA = hash('sha256', hex2bin($firstSHA));

		$checkSum = substr($secondSHA, 0, 8);
		$publicAddress = $version . $hash160 . $checkSum;
		$publicAddress = $this->base58->encode(hex2bin($publicAddress));
		return $publicAddress;
	}

	public function getPrivateKeyHex()
	{
		return $this->keyPair->getPrivate('hex');
	}

	public function getPrivateKeyWif()
	{
		$prefixedPrivateKey = '80' . $this->keyPair->getPrivate('hex');
		$firstPassSha256 = strtoupper(hash('sha256', hex2bin($prefixedPrivateKey)));
		$secondPassSha256 = strtoupper(hash('sha256', hex2bin($firstPassSha256)));
		$checksumString = substr($secondPassSha256, 0, 8);
		$checksummedPrivateKey = $prefixedPrivateKey . $checksumString;

		return $this->base58->encode(hex2bin($checksummedPrivateKey));
	}

	public function getPublicKeyHex()
	{
		return $this->keyPair->getPublic(false, 'hex');
	}
}


$bitCoinAddress = new BitcoinAddress();

$bitCoinAddress->fromSeedL('abc');
echo $bitCoinAddress->getPrivateKeyWif() . PHP_EOL;
echo $bitCoinAddress->getPrivateKeyHex() . PHP_EOL;
echo $bitCoinAddress->getPublicKeyHex() . PHP_EOL;
echo $bitCoinAddress->getAddress('00') . PHP_EOL;
