<?php

require 'index.php';
require 'indexReader.php';

function randomNumber(string $max = "1157920892373161954235709850086879078528375642790749043826051631415181614944")
{
    // Defina o valor máximo como uma string
    $maxValueString = $max;

    // Converta o valor máximo para GMP
    $maxValue = gmp_init($maxValueString);

    // Gere um número aleatório usando GMP
    $randomNumber = gmp_random_range(0, $maxValue);

    // Converta o resultado de volta para uma string
    $randomNumberString = gmp_strval($randomNumber);
    return $randomNumberString;
}

$btc = new BitcoinECDSA();

//file.txt with one address per line
$reader = new IndexedReader('./address.txt');

while (true) {

    $base = randomNumber();
    $decValue = hexdec($base);
    while ($decValue > 200) {
        $arr = [];
        echo $base . PHP_EOL;
        for ($i = 0; $i < 10; $i++) {
            $hex = gmp_strval(gmp_add($base, $i), 16);
            $btc->setPrivateKeyHex($hex);
            $address = $btc->getAddress();
            if ($reader->findValueByName($address)) {
                $arr[$btc->getWif()] = $address;
            }
        }
        for ($i = 10; $i > 0; $i--) {
            $hex = gmp_strval(gmp_sub($base, $i), 16);
            $btc->setPrivateKeyHex($hex);
            $address = $btc->getAddress();
            if ($reader->findValueByName($address)) {
                $arr[$btc->getWif()] = $address;
            }
        }
        if (!empty($arr)) {
            file_put_contents($base . '.json', json_encode($arr));
        }

        $base = randomNumber($base);
        $decValue = hexdec($base);
    }
}

