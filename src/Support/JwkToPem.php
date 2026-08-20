<?php

namespace Foziluff\SocialAuth\Support;

class JwkToPem
{
    /**
     * @param  array<string, string>  $jwk
     */
    public static function convert(array $jwk): ?string
    {
        if (! isset($jwk['kty']) || $jwk['kty'] !== 'RSA' || ! isset($jwk['n']) || ! isset($jwk['e'])) {
            return null;
        }

        $modulus = self::base64UrlDecode($jwk['n']);
        $exponent = self::base64UrlDecode($jwk['e']);

        $der = self::encodeDerSequence(
            self::encodeDerSequence(self::encodeDerOid('1.2.840.113549.1.1.1').self::encodeDerNull()).
            self::encodeDerBitString(self::encodeDerSequence(self::encodeDerInteger($modulus).self::encodeDerInteger($exponent)))
        );

        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    private static function base64UrlDecode(string $input): string
    {
        return base64_decode(strtr($input, '-_', '+/'));
    }

    private static function encodeLength(int $length): string
    {
        if ($length <= 127) {
            return chr($length);
        }

        $hexLength = ltrim(dechex($length), '0');
        if (strlen($hexLength) % 2 !== 0) {
            $hexLength = '0'.$hexLength;
        }

        $packed = hex2bin($hexLength);

        return chr(0x80 | strlen($packed)).$packed;
    }

    private static function encodeDerSequence(string $data): string
    {
        return chr(0x30).self::encodeLength(strlen($data)).$data;
    }

    private static function encodeDerOid(string $oid): string
    {
        $parts = explode('.', $oid);
        $first = (int) $parts[0] * 40 + (int) $parts[1];
        $data = chr($first);

        for ($i = 2; $i < count($parts); $i++) {
            $value = (int) $parts[$i];
            $bytes = [];
            do {
                $bytes[] = $value & 0x7F;
                $value >>= 7;
            } while ($value > 0);

            $bytes = array_reverse($bytes);
            for ($j = 0; $j < count($bytes) - 1; $j++) {
                $bytes[$j] |= 0x80;
            }

            foreach ($bytes as $byte) {
                $data .= chr($byte);
            }
        }

        return chr(0x06).self::encodeLength(strlen($data)).$data;
    }

    private static function encodeDerNull(): string
    {
        return chr(0x05).chr(0x00);
    }

    private static function encodeDerBitString(string $data): string
    {
        return chr(0x03).self::encodeLength(strlen($data) + 1).chr(0x00).$data;
    }

    private static function encodeDerInteger(string $data): string
    {
        if (ord($data[0]) > 0x7F) {
            $data = chr(0x00).$data;
        }

        return chr(0x02).self::encodeLength(strlen($data)).$data;
    }
}
