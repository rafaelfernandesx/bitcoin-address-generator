<?php
class ECDSA
{
    public $k;
    private $a;
    private $b;
    private $p;
    public $n;
    private $G;

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
    }

    private function doublePoint(array $pt)
    {
        $a = $this->a;
        $p = $this->p;

        $gcd = gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p), $p));
        if ($gcd !== '1') {
            throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }
        $slope = gmp_mod(gmp_mul(gmp_invert(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p), $p), gmp_add(gmp_mul(gmp_init(3, 10), gmp_pow($pt['x'], 2)), $a)), $p);
        $nPt = [];
        $nPt['x'] = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $pt['x']), $pt['x']), $p);
        $nPt['y'] = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($pt['x'], $nPt['x'])), $pt['y']), $p);

        return $nPt;
    }

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

        $slope = gmp_mod(gmp_mul(gmp_sub($pt1['y'], $pt2['y']), gmp_invert(gmp_sub($pt1['x'], $pt2['x']), $p)), $p);

        $nPt = [];
        $nPt['x'] = gmp_mod(gmp_sub(gmp_sub(gmp_pow($slope, 2), $pt1['x']), $pt2['x']), $p);

        $nPt['y'] = gmp_mod(gmp_sub(gmp_mul($slope, gmp_sub($pt1['x'], $nPt['x'])), $pt1['y']), $p);

        return $nPt;
    }

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

    private function validatePoint(string $x, string $y): bool
    {
        $a = $this->a;
        $b = $this->b;
        $p = $this->p;

        $x = gmp_init($x, 16);
        $y2 = gmp_mod(gmp_add(gmp_add(gmp_powm($x, gmp_init(3, 10), $p), gmp_mul($a, $x)), $b), $p);
        $y = gmp_mod(gmp_pow(gmp_init($y, 16), 2), $p);

        if (gmp_cmp($y2, $y) === 0)
            return true;
        else
            return false;
    }

    public function getPubKeyPoints(): array
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
            $compressedPubKey = '02' . $pubKeyPts['x'];    //if $pubKey['y'] is even
        else
            $compressedPubKey = '03' . $pubKeyPts['x'];    //if $pubKey['y'] is odd

        return $compressedPubKey;
    }
}
