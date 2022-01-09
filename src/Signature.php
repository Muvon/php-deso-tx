<?php
namespace Muvon\DeSo;

use Elliptic\EC;

class Signature {
  public static function sign(string $hash, string $key): string {
    $ec = new EC('secp256k1');
    $ecPrivateKey = $ec->keyFromPrivate($key, 'hex');
    $signature = $ecPrivateKey->sign($hash, ['canonical' => true]);

    $r = '';
    foreach ($signature->toDER() as $chr) {
      $r .= chr($chr);
    }
    return bin2hex($r);
  }

  // https://github.com/simplito/elliptic-php
  public static function validate(string $hash, string $signature, string $pubkey): bool {
    return (new EC('secp256k1'))->verify($hash, bin2hex($signature), $pubkey);
  }
}