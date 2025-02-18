<?php
require_once __DIR__ . '/bip39_wordlist_english.php';
require_once __DIR__ . '/bip39_wordlist_portuguese.php';
class BIP39
{
    private const HMAC_KEY = "Bitcoin seed";
    private const HARDENED_OFFSET = 0x80000000; // 2³¹
    static private array $wordList;

    public static function setWordList(string $wordLanguage = "english")
    {
        self::$wordList = (new WordListEnglish())->getWordList();

        if ($wordLanguage == 'portuguese') {
            self::$wordList = (new WordListPortuguese())->getWordList();
        }
        if (count(self::$wordList) !== 2048) {
            throw new Exception("A lista de palavras deve conter exatamente 2048 palavras.");
        }
    }

    // 🔹 Gera uma entropia segura de 128 a 256 bits
    public static function generateEntropy(int $bits = 128): string
    {
        if (!in_array($bits, [128, 160, 192, 224, 256])) {
            throw new Exception("O tamanho da entropia deve ser 128, 160, 192, 224 ou 256 bits.");
        }
        return random_bytes($bits / 8);
    }

    // 🔹 Calcula o checksum da entropia (SHA-256)
    private static function getChecksum(string $entropy): string
    {
        $hash = hash('sha256', $entropy, true);
        $checksumBits = strlen($entropy) * 8 / 32;  // Ex: 128 bits de entropia => 4 bits de checksum
        return substr(decbin(ord($hash[0])), 0, $checksumBits);
    }

    // 🔹 Converte entropia em uma frase mnemônica
    public static function entropyToMnemonic(string $entropy, string $wordLanguage = "english"): string
    {
        $binaryEntropy = '';
        foreach (str_split(bin2hex($entropy), 2) as $hex) {
            $binaryEntropy .= str_pad(decbin(hexdec($hex)), 8, '0', STR_PAD_LEFT);
        }

        $binaryEntropy .= BIP39::getChecksum($entropy); // Adiciona o checksum
        self::setWordList($wordLanguage);

        // Divide em grupos de 11 bits e converte em palavras
        $words = [];
        for ($i = 0; $i < strlen($binaryEntropy); $i += 11) {
            $index = bindec(substr($binaryEntropy, $i, 11));
            $words[] = self::$wordList[$index];
        }

        return implode(" ", $words);
    }

    // 🔹 Converte uma frase mnemônica em semente (PBKDF2)
    public static function mnemonicToSeed(string $mnemonic, string $passphrase = ""): string
    {
        $salt = "mnemonic" . $passphrase;
        return hash_pbkdf2("sha512", $mnemonic, $salt, 2048, 64, true);
    }

    public static function seedToMasterKey(string $seed): array
    {
        $hmac = hash_hmac("sha512", $seed, self::HMAC_KEY, true);
        return [
            "privateKey" => substr($hmac, 0, 32), // Primeiros 32 bytes
            "chainCode" => substr($hmac, 32, 32)  // Últimos 32 bytes
        ];
    }

    public static function deriveChildKey(array $parentKey, int $index, bool $hardened = false): array
    {
        $index = $hardened ? ($index | self::HARDENED_OFFSET) : $index;

        if ($hardened) {
            $data = "\x00" . $parentKey['privateKey'] . pack("N", $index);
        } else {
            $publicKey = self::privateKeyToPublicKey($parentKey['privateKey']);
            $data = $publicKey . pack("N", $index);
        }

        $hmac = hash_hmac("sha512", $data, $parentKey['chainCode'], true);
        $newPrivateKey = substr($hmac, 0, 32);
        $newChainCode = substr($hmac, 32, 32);

        return [
            "privateKey" => $newPrivateKey,
            "chainCode" => $newChainCode
        ];
    }

    public static function privateKeyToPublicKey(string $privateKey): string
    {
        $secp256k1 = new ECDSA();
        $secp256k1->k = bin2hex($privateKey);
        $pub = $secp256k1->getPubKey();
        $pub = hex2bin($pub);
        return $pub;
    }
}

// // 🛠 Uso da classe
// try {
//     $bip39 = new BIP39();

//     // 🔥 Gerar entropia e converter em mnemônico
//     // $entropy = $bip39->generateEntropy(128);  // 128 bits
//     $mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'; //$bip39->entropyToMnemonic($entropy);

//     echo "Frase mnemônica: " . $mnemonic . PHP_EOL;

//     // 🔥 Converter frase mnemônica em semente
//     $seed = $bip39->mnemonicToSeed($mnemonic, "");

//     $masterKey = $bip39->seedToMasterKey(bin2hex($seed));
//     echo "Semente gerada: " . bin2hex($seed) . PHP_EOL;
//     echo "masterKey: " . bin2hex($masterKey['privateKey']) . PHP_EOL;
// } catch (Exception $e) {
//     echo "Erro: " . $e->getMessage() . PHP_EOL;
// }
