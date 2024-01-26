<?php

require 'index.php';
require 'indexReader.php';

function randomNumber()
{
    // Defina o valor máximo como uma string
    $maxValueString = "1157920892373161954235709850086879078528375642790749043826051631415181614944";

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
    $arr = [];
    echo $base = randomNumber();
    echo PHP_EOL;
    for ($i = 0; $i < 1000; $i++) {
        $hex = gmp_strval(gmp_add($base, $i), 16);
        $btc->setPrivateKeyHex($hex);
        if ($reader->findValueByName($btc->getAddress())) {
            $arr[$btc->getWif()] = $btc->getAddress();
        }
    }
    for ($i = 1000; $i > 0; $i--) {
        $hex = gmp_strval(gmp_sub($base, $i), 16);
        $btc->setPrivateKeyHex($hex);
        if ($reader->findValueByName($btc->getAddress())) {
            $arr[$btc->getWif()] = $btc->getAddress();
        }
    }
    if (!empty($arr)) {
        file_put_contents($base . '.json', json_encode($arr));
    }
}
