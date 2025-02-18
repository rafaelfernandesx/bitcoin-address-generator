<?php

require 'index.php';
require 'indexReader.php';


$btc = new BitcoinTOOL();

//file.txt with one address per line
$reader = new IndexedReader('./address.txt');
$arr = [];
while (true) {

    $mnemonic = $btc->setPrivateKeyFromRandomMnemonic('');
    $address = $btc->getAddress();
    $addressc = $btc->getAddress(true);
    if ($reader->findValueByName($address)) {
        $arr[$btc->getWif()] = $address . '-' . $mnemonic;
    }

    if ($reader->findValueByName($addressc)) {
        $arr[$btc->getWif()] = $addressc;
    }
    if (!empty($arr)) {
        file_put_contents($mnemonic . '.json', json_encode($arr));
    }
}
