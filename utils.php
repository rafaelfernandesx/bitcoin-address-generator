<?php

require 'index.php';

class BtcUtils
{
    public static BitcoinTOOL $btc;


    static public function pubKeyHexToAddress(string $pubKeyHex)
    {
        $address = $pubKeyHex;

        $address = SELF::$btc->getNetworkPrefix() . SELF::$btc->hash160(hex2bin($address));

        //checksum
        $address = $address . substr(SELF::$btc->hash256d(hex2bin($address)), 0, 8);
        $address = Base58::encode($address);

        if (SELF::$btc->validateAddress($address))
            return $address;
        else
            throw new \Exception('the generated address seems not to be valid.');
    }

    static public function pubKeyToAddress(string $pubKey)
    {
        $address = $pubKey;

        $address = SELF::$btc->getNetworkPrefix() . SELF::$btc->hash160($address);

        //checksum
        $address = $address . substr(SELF::$btc->hash256d(hex2bin($address)), 0, 8);
        $address = Base58::encode($address);

        if (SELF::$btc->validateAddress($address))
            return $address;
        else
            throw new \Exception('the generated address seems not to be valid.');
    }

    static public function wifToHex(string $wif)
    {
        // Decodificar o WIF usando Base58
        $decoded = Base58::decode($wif);
        if ($decoded === null) {
            return null;
        }

        // O comprimento esperado de uma chave WIF decodificada é de 37 bytes
        // Prefixo (1 byte) + Chave privada (32 bytes) + Checksum (4 bytes)
        if (strlen($decoded) !== 74) { // 37 bytes em hexadecimal
            return null;
        }

        // Remover o checksum (últimos 4 bytes)
        $withoutChecksum = substr($decoded, 0, -8);

        // Remover o prefixo da rede (primeiros 2 caracteres)
        $privateKeyHex = substr($withoutChecksum, 2);

        return $privateKeyHex;
    }

    static public function hexToWif(string $privateKeyHex, $isCompressed = false, $isMainnet = true)
    {
        // Passo 1: Prefixo da rede
        $prefix = $isMainnet ? '80' : 'ef'; // 80 para mainnet, ef para testnet
        $keyWithPrefix = $prefix . $privateKeyHex;

        // Passo 2: Adicionar byte de compressão se necessário
        if ($isCompressed) {
            $keyWithPrefix .= '01';
        }

        // Passo 3: Calcular o checksum (hash duplo SHA256)
        $hash1 = hash('sha256', hex2bin($keyWithPrefix));
        $hash2 = hash('sha256', hex2bin($hash1));
        $checksum = substr($hash2, 0, 8); // Pegando os primeiros 4 bytes (8 caracteres hexadecimais)

        // Passo 4: Adicionar o checksum ao final da chave
        $keyWithChecksum = $keyWithPrefix . $checksum;

        // Passo 5: Converter de hexadecimal para Base58
        $wif = Base58::encode(hex2bin($keyWithChecksum));

        return $wif;
    }

    static public function ripmd160ToAddress(string $ripmd160)
    {

        $address = SELF::$btc->getNetworkPrefix() . $ripmd160;

        //checksum
        $address = $address . substr(SELF::$btc->hash256d(hex2bin($address)), 0, 8);
        $address = Base58::encode($address);

        if (SELF::$btc->validateAddress($address))
            return $address;
        else
            throw new \Exception('the generated address seems not to be valid.');
    }
}
BtcUtils::$btc = new BitcoinTOOL();
