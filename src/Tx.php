<?php
namespace Muvon\DeSo;

use Muvon\KISS\VarInt;
use Muvon\KISS\Base58Codec;
use InvalidArgumentException;

// https://github.com/bitclout/core/blob/main/lib/network.go
class Tx {
  const NETWORK_PREFIX = 'cd1400';
  const ARCHITECT_PUBKEY_HEX = '8mkU8yaVLs';
  const ARCHITECT_PUBKEY = '';

  const UNSET = 0;
  const BLOCK_REWARD = 1; // not implemented
  const BASIC_TRANSFER = 2; // null meta
  const BITCOIN_EXCHANGE = 3; // not implemented
  const PRIVATE_MESSAGE = 4;
  const SUBMIT_POST = 5;
  const UPDATE_PROFILE = 6;
  const UPDATE_BITCOIN_USD_EXCHANGE_RATE = 8;
  const FOLLOW = 9;
  const LIKE = 10;
  const CREATOR_COIN = 11;
  const SWAP_IDENTITY = 12;
  const UPDATE_GLOBAL_PARAMS = 13; // meta in extra
  const CREATOR_COIN_TRANSFER = 14;
  const CREATE_NFT = 15;
  const UPDATE_NFT = 16;
  const ACCEPT_NFT_BID = 17;
  const NFT_BID = 18;
  const NFT_TRANSFER = 19; // not implemented
  const ACCEPT_NFT_TRANSFER = 20; // not implemented
  const BURN_NFT = 21; // not implemented
  const AUTHORIZE_DERIVED_KEY = 22; // not implemented

  // Creator Coin operations
  const COIN_BUY = 0;
  const COIN_SELL = 1;
  const COIN_ADD = 2;

  const DERIVE_FORBID = 0;
  const DERIVE_GRANT = 1;

  const BOOL_KEYS = [
    'IsQuotedReclout',
  ];

  const UINT_KEYS = [
    'USDCentsPerBitcoin',
    'MinNetworkFeeNanosPerKB',
    'CreateProfileFeeNanos',
    'CreateNFTFeeNanos',
    'MaxCopiesPerNFT',
  ];

  const INT_KEYS = [
    'DiamondLevel',
  ];

  public static function fromHex(string $hex, bool $use_hex = false): array {
    return static::fromBin(hex2bin($hex), $use_hex);
  }

  public static function fromBin(string $bin, bool $use_hex = false): array {
    $tx_id = static::getTxId($bin);

    [$inputs, $offset] = static::readInputs($bin, 0, $use_hex);
    [$outputs, $offset] = static::readOutputs($bin, $offset, $use_hex);

    [$type_id, $offset] = VarInt::readUint($bin, $offset);
    [$meta_len, $offset] = VarInt::readUint($bin, $offset);

    $meta_raw = substr($bin, $offset, $meta_len);
    $m_offset = 0;
    $meta = [];

    switch ($type_id) {
      case static::UNSET:
        throw new InvalidArgumentException('UNSET is not supported');
        break;

      case static::BLOCK_REWARD:
        [$meta['extra_data'], $m_offset] = static::readString($meta_raw, $m_offset, $use_hex);
        break;

      case static::BITCOIN_EXCHANGE:
        [$tx_bin, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['tx_raw'] = static::adaptHex($tx_bin, $use_hex);
        $meta['block_hash'] = static::reverseHash(bin2hex(substr($meta_raw, $m_offset, 32)));
        $m_offset += 32;
        $meta['merkle_root'] = static::reverseHash(bin2hex(substr($meta_raw, $m_offset, 32)));
        $m_offset += 32;

        [$proof_count, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['merkle_proof'] = [];
        while ($proof_count-- > 0) {
          $meta['merkle_proof'][] = static::reverseHash(bin2hex(substr($meta_raw, $m_offset, 33)));
          $m_offset += 33;
        }

        $meta['tx_id'] = static::reverseHash(static::getTxHashHex($tx_bin));
        unset($tx_bin);
        break;

      case static::PRIVATE_MESSAGE:
        $pubkey = substr($meta_raw, $m_offset, 33);
        $meta['pubkey'] = static::adaptBase58Check($pubkey, $use_hex);
        $m_offset += 33;
        [$meta['text'], $m_offset] =  static::readString($meta_raw, $m_offset, $use_hex);
        [$meta['timestamp_nanos'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::SUBMIT_POST:
        [$meta['post_hash'], $m_offset] = static::readString($meta_raw, $m_offset, $use_hex);
        [$meta['parent_post_hash'], $m_offset] = static::readString($meta_raw, $m_offset, $use_hex);
        [$body, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['data'] = json_decode($body, true);
        [$meta['reward_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['stake_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['timestamp_nanos'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['is_hidden'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        break;

      case static::UPDATE_PROFILE:
        [$pubkey, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey'] = static::adaptBase58Check($pubkey, $use_hex);

        [$meta['username'], $m_offset] = static::readString($meta_raw, $m_offset);
        [$meta['description'], $m_offset] = static::readString($meta_raw, $m_offset);

        [$meta['avatar'], $m_offset] = static::readString($meta_raw, $m_offset);

        [$meta['reward_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['stake_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['is_hidden'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);

        break;

      case static::UPDATE_BITCOIN_USD_EXCHANGE_RATE:
        [$meta['btc_usd_rate'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::FOLLOW:
        $meta['pubkey'] = static::adaptBase58Check(substr($meta_raw, $m_offset, 33), $use_hex);
        $m_offset += 33;

        [$meta['is_unfollow'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);

        break;

      case static::LIKE:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, $m_offset, 32), $use_hex);
        $m_offset += 32;
        [$meta['is_unlike'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        break;

      case static::CREATOR_COIN:
        // pubkey
        [$pubkey_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        // Creator pubkey
        $meta['pubkey'] = static::adaptBase58Check(substr($meta_raw, $m_offset, $pubkey_len), $use_hex);

        $m_offset += $pubkey_len;
        $meta['operation_id'] = ord(substr($meta_raw, $m_offset, 1));
        ++$m_offset;

        [$meta['spend'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['coins'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['add'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['value_expected'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['coins_expected'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::SWAP_IDENTITY:
        [$pubkey1, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey1'] = static::adaptBase58Check($pubkey1, $use_hex);

        [$pubkey2, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey2'] = static::adaptBase58Check($pubkey2, $use_hex);
        break;

      case static::CREATOR_COIN_TRANSFER:
        // creator pubkey
        [$pubkey_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['pubkey'] = static::adaptBase58Check(substr($meta_raw, $m_offset, $pubkey_len), $use_hex);
        $m_offset += $pubkey_len;

        // Coins to transfer
        [$meta['amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);

        // Receiver
        [$pubkey_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['receiver'] = static::adaptBase58Check(substr($meta_raw, $m_offset, $pubkey_len), $use_hex);
        $m_offset += $pubkey_len;
        break;

      case static::CREATE_NFT:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, 0, 32), $use_hex);
        $m_offset += 32;

        [$meta['num_copies'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['has_unlockable'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        [$meta['is_selling'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        [$meta['min_bid_amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['royalty_to_creator_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['royalty_to_coin_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::UPDATE_NFT:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, 0, 32), $use_hex);
        $m_offset += 32;

        [$meta['serial'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['is_selling'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        [$meta['min_bid_amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::ACCEPT_NFT_BID:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, 0, 32), $use_hex);
        $m_offset += 32;

        [$meta['serial'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$pubkey, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey'] = static::adaptBase58Check($pubkey, $use_hex);
        [$meta['amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$unlockable_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['unlockable_text'] = static::adaptHex(substr($meta_raw, $m_offset, $unlockable_len), $use_hex);
        $m_offset += $unlockable_len;
        [$meta['inputs'], $m_offset] = static::readInputs($meta_raw, $m_offset, $use_hex);
        break;

      case static::NFT_BID:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, 0, 32), $use_hex);
        $m_offset += 32;

        [$meta['serial'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::NFT_TRANSFER:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, 0, 32), $use_hex);
        $m_offset += 32;

        [$meta['serial'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);

        [$pubkey, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey'] = static::adaptBase58Check($pubkey, $use_hex);

        [$unlockable_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['unlockable_text'] = static::adaptHex(substr($meta_raw, $m_offset, $unlockable_len), $use_hex);
        $m_offset += $unlockable_len;
        break;


      case static::ACCEPT_NFT_TRANSFER:
      case static::BURN_NFT:
        $meta['post_hash'] = static::adaptHex(substr($meta_raw, 0, 32), $use_hex);
        $m_offset += 32;

        [$meta['serial'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::AUTHORIZE_DERIVED_KEY:
        [$pubkey, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey'] = static::adaptBase58Check($pubkey, $use_hex);

        [$meta['expiration_height'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['operation_id'] = ord(substr($meta_raw, $m_offset, 1));
        ++$m_offset;

        // AccessSignature is the signed hash of (derivedPublicKey + expirationBlock)
	      // made with the ownerPublicKey. Signature is in the DER format.
        [$meta['signature'], $m_offset] = static::readString($meta_raw, $m_offset, $use_hex);
        break;
    }

    $offset += $meta_len;
    [$transactor_len, $offset] = VarInt::readUint($bin, $offset);
    $transactor = static::adaptBase58Check(substr($bin, $offset, $transactor_len), $use_hex);
    $offset += $transactor_len;
    [$extra_count, $offset] = VarInt::readUint($bin, $offset);
    $extra_data = [];
    while ($extra_count-- > 0) {
      [$key_len, $offset] = VarInt::readUint($bin, $offset);
      $key = substr($bin, $offset, $key_len);
      $offset += $key_len;
      [$val_len, $offset] = VarInt::readUint($bin, $offset);
      if (in_array($key, static::UINT_KEYS)) {
        [$val, $offset] = VarInt::readUint($bin, $offset);
      } elseif (in_array($key, static::INT_KEYS)) {
        [$val, $offset] = VarInt::readInt($bin, $offset);
      } elseif (in_array($key, static::BOOL_KEYS)) {
        [$val, $offset] = VarInt::readBool($bin, $offset);
      } else {
        $val = static::adaptHex(substr($bin, $offset, $val_len), $use_hex);
        $offset += $val_len;
      }
      $extra_data[$key] = $val;
    }

    [$sign_len, $offset] = VarInt::readUint($bin, $offset);
    $signature = substr($bin, $offset, $sign_len);
    $offset += $sign_len;

    // If isset we did not parse full tx
    // var_dump(isset($hex[$offset]));

    $tx_bin = substr($bin, 0, $offset);
    return [
      'id' => $tx_id,
      'transactor' => $transactor,
      'type_id' => $type_id,
      'inputs' => $inputs,
      'outputs' => $outputs,
      'signature' => $use_hex ? bin2hex($signature) : $signature,
      'meta' => $meta,
      'extra' => $extra_data,
      'size' => strlen($tx_bin),
      'raw' => $use_hex ? bin2hex($tx_bin) : $tx_bin,
    ];
  }

  public static function toHex(array $tx, string $private_key = ''): string {
    $bin = static::writeInputs($tx['inputs']) . static::writeOutputs($tx['outputs']);
    $bin .= VarInt::packUint($tx['type_id']);
    $meta = '';
    switch ($tx['type_id']) {
      case static::CREATOR_COIN:
        $creator = static::base58CheckToBin($tx['meta']['creator']);
        $meta .= VarInt::packUint(strlen($creator));
        $meta .= $creator;
        $meta .= chr($tx['meta']['operation_id']);
        $meta .= VarInt::packUint($tx['meta']['spend'] ?? 0);
        $meta .= VarInt::packUint($tx['meta']['coins'] ?? 0);
        $meta .= VarInt::packUint($tx['meta']['add'] ?? 0);
        $meta .= VarInt::packUint($tx['meta']['amount_expected'] ?? 0);
        $meta .= VarInt::packUint($tx['meta']['coin_expected'] ?? 0);
        break;
    }
    $bin .= VarInt::packUint(strlen($meta));
    $bin .= $meta;

    // transactor
    $transactor = static::base58CheckToBin($tx['transactor']);
    $bin .= VarInt::packUint(strlen($transactor));
    $bin .= $transactor;

    // extra
    $bin .= VarInt::packUint(0);

    $signature = $tx['signature'] ?? ($private_key ? static::signTransaction($bin . "\0", $private_key) : '');
    // zero len signature
    $bin .= $signature ? VarInt::packUint(strlen($signature)) . $signature : "\0";
    return bin2hex($bin);
  }

  public static function adaptHex(string $str, bool $use_hex): string {
    return $use_hex ? bin2hex($str) : $str;
  }

  public static function adaptBase58Check(string $str, bool $use_hex): string {
    return $use_hex ? static::binToBase58Check($str) : $str;
  }
  public static function getTypeMap(): array {
    return [
      static::UNSET => 'UNSET',
      static::BLOCK_REWARD => 'BLOCK_REWARD',
      static::BASIC_TRANSFER => 'BASIC_TRANSFER',
      static::BITCOIN_EXCHANGE => 'BITCOIN_EXCHANGE',
      static::PRIVATE_MESSAGE => 'PRIVATE_MESSAGE',
      static::SUBMIT_POST => 'SUBMIT_POST',
      static::UPDATE_PROFILE => 'UPDATE_PROFILE',
      static::UPDATE_BITCOIN_USD_EXCHANGE_RATE => 'UPDATE_BITCOIN_USD_EXCHANGE_RATE',
      static::FOLLOW => 'FOLLOW',
      static::LIKE => 'LIKE',
      static::CREATOR_COIN => 'CREATOR_COIN',
      static::SWAP_IDENTITY => 'SWAP_IDENTITY',
      static::UPDATE_GLOBAL_PARAMS => 'UPDATE_GLOBAL_PARAMS',
      static::CREATOR_COIN_TRANSFER => 'CREATOR_COIN_TRANSFER',
      static::CREATE_NFT => 'CREATE_NFT',
      static::UPDATE_NFT => 'UPDATE_NFT',
      static::ACCEPT_NFT_BID => 'ACCEPT_NFT_BID',
      static::NFT_BID => 'NFT_BID',
      static::NFT_TRANSFER => 'NFT_TRANSFER',
      static::ACCEPT_NFT_TRANSFER => 'ACCEPT_NFT_TRANSFER',
      static::BURN_NFT => 'BURN_NFT',
      static::AUTHORIZE_DERIVED_KEY => 'AUTHORIZE_DERIVED_KEY',
    ];
  }
  public static function getType(int $type_id): string {
    return static::getTypeMap()[$type_id] ?? '';
  }

  public static function getCreatorCoinOperationMap(): array {
    return [
      static::COIN_BUY => 'buy',
      static::COIN_SELL => 'sell',
      static::COIN_ADD => 'add',
    ];
  }

  public static function getCreatorCoinOperation(int $operation_id): string {
    return static::getCreatorCoinOperationMap()[$operation_id] ?? '';
  }

  public static function getTxId(string $bin): string {
    // Special case for BITCOIN_EXCHANGE
    if (substr($bin, 0, 3) === "\0\0\3") {
      [$meta_len, $offset] = VarInt::readUint($bin, 3);
      [$bin, $offset] = static::readString($bin, $offset);
      return static::hexToBase58Check(static::getTxHashHex($bin));
    }
    $tx_id = static::hexToBase58Check(static::getTxHashHex($bin));
    // Genesis block work around
    if ($tx_id === '3JuEUEgf48j68DJPn7M4RMNpBxHZo221sYm39hatrnMyUdDVyC6w3F') {
      $tx_id = '3JuESjmiiRsfbF4AKB6y9QUMj6iAN24abbSBBhh69JxqfwPLHqW53k';
    }
    return $tx_id;
  }

  public static function hexToBase58Check(string $hex): string {
    return Base58Codec::checkEncode(static::NETWORK_PREFIX . $hex);
  }

  public static function binToBase58Check(string $bin): string {
    return static::hexToBase58Check(bin2hex($bin));
  }


  public static function base58CheckToHex(string $base58): string {
    return substr(Base58Codec::checkDecode($base58), 6);
  }

  public static function base58CheckToBin(string $base58): string {
    return hex2bin(static::base58CheckToHex($base58));
  }

  public static function getAffectedPubkeys(array $tx): array {
    $pubkeys = array_column($tx['outputs'], 0);

    $pubkeys[] = $tx['transactor'];
    if (isset($tx['meta']['pubkey'])) {
      $pubkeys[] = $tx['meta']['pubkey'];
    }
    if (isset($tx['meta']['pubkey1'])) {
      $pubkeys[] = $tx['meta']['pubkey1'];
    }
    if (isset($tx['meta']['pubkey2'])) {
      $pubkeys[] = $tx['meta']['pubkey2'];
    }
    if (isset($tx['meta']['receiver'])) {
      $pubkeys[] = $tx['meta']['receiver'];
    }
    return array_unique($pubkeys);
  }
  protected static function readString(string $bin, int $offset = 0, bool $is_hex = false): array {
    [$len, $offset] = VarInt::readUint($bin, $offset);
    $str = substr($bin, $offset, $len);
    return [$is_hex ? bin2hex($str) : $str, $offset + $len];
  }

  protected static function readInputs(string $bin, int $offset = 0, bool $use_hex = false): array {
    $inputs = [];
    [$input_cnt, $offset] = VarInt::readUint($bin, $offset);
    while ($input_cnt-- > 0) {
      $tx_id = substr($bin, $offset, 32);
      $offset += 32;
      [$index, $offset] = VarInt::readUint($bin, $offset);
      $inputs[] = [static::adaptBase58Check($tx_id, $use_hex), $index];
    }
    return [$inputs, $offset];
  }

  protected static function writeInputs(array $inputs): string {
    $bin = VarInt::packUint(sizeof($inputs));
    foreach ($inputs as [$tx_id, $index]) {
      $bin .= static::base58CheckToBin($tx_id) . VarInt::packUint($index);
    }
    return $bin;
  }


  protected static function readOutputs(string $bin, int $offset = 0, bool $use_hex = false): array {
    $outputs = [];
    [$output_cnt, $offset] = VarInt::readUint($bin, $offset);
    while ($output_cnt-- > 0) {
      $pubkey = substr($bin, $offset, 33);
      $offset += 33;
      [$nanos, $offset] = VarInt::readUint($bin, $offset);
      $outputs[] = [static::adaptBase58Check($pubkey, $use_hex), $nanos];
    }
    return [$outputs, $offset];
  }

  protected static function writeOutputs(array $outputs): string {
    $bin = VarInt::packUint(sizeof($outputs));
    foreach ($outputs as [$pubkey, $nanos]) {
      $bin .= static::base58CheckToBin($pubkey) . VarInt::packUint($nanos);
    }
    return $bin;
  }

  protected static function getTxHashHex(string $raw): string {
    return hash('sha256', hash('sha256', $raw, true));
  }

  public static function signTransaction(string $tx, string $key): string {
    return hex2bin(Signature::sign(static::getTxHashHex($tx), $key));
  }

  public static function validateSignature(string $tx, string $signature, string $pubkey): bool {
    $signature_len = strlen(VarInt::packUint(strlen($signature)) . $signature);
    $signed_raw = substr($tx, 0, -$signature_len) . "\0";
    return Signature::validate(static::getTxHashHex($signed_raw), $signature, $pubkey);
  }

  protected static function reverseHash(string $hash): string {
    return implode('', array_reverse(str_split($hash, 2)));
  }
}
