<?php
namespace Muvon\Bitclout;

use InvalidArgumentException;
use Muvon\KISS\VarInt;
use Muvon\KISS\Base58Codec;
// https://github.com/bitclout/core/blob/main/lib/network.go
class Tx {
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

  const BOOL_KEYS = [
    'IsQuotedReclout',
  ];

  const UINT_KEYS = [
    'USDCentsPerBitcoin',
    'MinNetworkFeeNanosPerKB',
    'CreateProfileFeeNanosKey',
    'CreateNFTFeeNanos',
    'MaxCopiesPerNFT',
  ];

  const INT_KEYS = [
    'DiamondLevel',
  ];

  public static function fromBin(string $bin): array {
    return static::fromHex(bin2hex($bin));
  }

  public static function fromHex(string $hex): array {
    [$inputs, $offset] = static::readInputs($hex, 0);

    $outputs = [];
    [$output_cnt, $offset] = VarInt::readUint($hex, $offset);
    while ($output_cnt-- > 0) {
      $pubkey_hex = substr($hex, $offset, 66);
      $offset += 66;
      [$nanos, $offset] = VarInt::readUint($hex, $offset);
      $outputs[] = [static::hexToBase58Check($pubkey_hex), $nanos];
    }

    [$type_id, $offset] = VarInt::readUint($hex, $offset);
    [$meta_len, $offset] = VarInt::readUint($hex, $offset);

    $meta_raw = substr($hex, $offset, $meta_len * 2);
    $m_offset = 0;
    $meta = [];

    switch ($type_id) {
      case static::UNSET:
        throw new InvalidArgumentException('UNSET is not supported');
        break;

      case static::BLOCK_REWARD:
        [$meta['extra_data_hex'], $m_offset] = static::readString($meta_raw, $m_offset);
        break;

      case static::PRIVATE_MESSAGE:
        $pubkey_hex = substr($meta_raw, $m_offset, 66);
        $meta['pubkey'] = static::hexToBase58Check($pubkey_hex);
        $m_offset += 66;
        [$meta['text_hex'], $m_offset] =  static::readString($meta_raw, $m_offset);
        [$meta['timestamp_nanos'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::SUBMIT_POST:
        [$meta['post_hex'], $m_offset] = static::readString($meta_raw, $m_offset);
        [$meta['parent_post_hex'], $m_offset] = static::readString($meta_raw, $m_offset);
        [$body_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['data'] = json_decode(hex2bin($body_hex), true);
        [$meta['reward_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['stake_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['timestamp_nanos'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['is_hidden'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        break;

      case static::UPDATE_PROFILE:
        [$pubkey_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey'] = static::hexToBase58Check($pubkey_hex);
        
        [$username_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['username'] = hex2bin($username_hex);

        [$description_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['description'] = hex2bin($description_hex);

        [$avatar_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['avatar'] = hex2bin($avatar_hex);

        [$meta['reward_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['stake_point'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['is_hidden'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);

        break;

      case static::UPDATE_BITCOIN_USD_EXCHANGE_RATE:
        [$meta['btc_usd_rate'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;
      
      case static::FOLLOW:
        $pubkey_hex = substr($meta_raw, $m_offset, 66);
        $meta['pubkey'] = static::hexToBase58Check($pubkey_hex);
        $m_offset += 66;

        [$meta['is_unfollow'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        
        break;
      
      case static::LIKE:
        $meta['post_hex'] = substr($meta_raw, $m_offset, 64);
        $m_offset += 64;
        [$meta['is_unlike'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        break;

      case static::CREATOR_COIN:
        // pubkey
        [$pubkey_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $pubkey_hex = substr($meta_raw, $m_offset, $pubkey_len * 2);
        $meta['creator'] = static::hexToBase58Check($pubkey_hex);

        $m_offset += $pubkey_len * 2;

        [$meta['operation_id'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $m_offset += 2;

        [$meta['spend'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['coins'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['add'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['amount_expected'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['coin_expected'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::SWAP_IDENTITY:
        [$pubkey_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey1'] = static::hexToBase58Check($pubkey_hex);

        [$pubkey_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey2'] = static::hexToBase58Check($pubkey_hex);
        break;

      case static::CREATOR_COIN_TRANSFER:
        // creator pubkey
        [$pubkey_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $pubkey_hex = substr($meta_raw, $m_offset, $pubkey_len * 2);
        $meta['creator'] = static::hexToBase58Check($pubkey_hex);
        $m_offset += $pubkey_len * 2;
        
        // Coins to transfer
        [$meta['amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);

        // Receiver
        [$pubkey_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $pubkey_hex = substr($meta_raw, $m_offset, $pubkey_len * 2);
        $meta['receiver'] = static::hexToBase58Check($pubkey_hex);
        $m_offset += $pubkey_len * 2;
        break;

      case static::CREATE_NFT:
        $meta['post_hex'] = substr($meta_raw, 0, 64);
        $m_offset += 64;

        [$meta['num_copies'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['has_unlockable'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        [$meta['is_for_sale'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        [$meta['min_bid_amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['royalty_to_creator_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['royalty_to_coin_points'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::UPDATE_NFT:
        $meta['post_hex'] = substr($meta_raw, 0, 64);
        $m_offset += 64;

        [$meta['serial_number'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['is_for_sale'], $m_offset] = VarInt::readBool($meta_raw, $m_offset);
        [$meta['min_bid_amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;

      case static::ACCEPT_NFT_BID:
        $meta['post_hex'] = substr($meta_raw, 0, 64);
        $m_offset += 64;

        [$meta['serial_number'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$pubkey_hex, $m_offset] = static::readString($meta_raw, $m_offset);
        $meta['pubkey'] = static::hexToBase58Check($pubkey_hex);
        [$meta['amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$unlockable_len, $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        $meta['unlockable_text'] = substr($meta_raw, $m_offset, $unlockable_len * 2);
        $m_offset += $unlockable_len * 2;
        [$meta['inputs'], $m_offset] = static::readInputs($meta_raw, $m_offset);
        break;

      case static::NFT_BID:
        $meta['post_hex'] = substr($meta_raw, 0, 64);
        $m_offset += 64;

        [$meta['serial_number'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        [$meta['amount'], $m_offset] = VarInt::readUint($meta_raw, $m_offset);
        break;
    }

    $offset += $meta_len * 2;
    [$transactor_len, $offset] = VarInt::readUint($hex, $offset);
    $transactor = static::hexToBase58Check(substr($hex, $offset, $transactor_len * 2));
    $offset += $transactor_len * 2;
    [$extra_count, $offset] = VarInt::readUint($hex, $offset);
    $extra_data = [];
    while ($extra_count-- > 0) {
      [$key_len, $offset] = VarInt::readUint($hex, $offset);
      $key = hex2bin(substr($hex, $offset, $key_len * 2));
      $offset += $key_len * 2;
      [$val_len, $offset] = VarInt::readUint($hex, $offset);
      if (in_array($key, static::UINT_KEYS)) {
        [$val, $offset] = VarInt::readUint($hex, $offset);
      } elseif (in_array($key, static::INT_KEYS)) {
        [$val, $offset] = VarInt::readInt($hex, $offset);
      } elseif (in_array($key, static::BOOL_KEYS)) {
        [$val, $offset] = VarInt::readBool($hex, $offset);
      } else {
        $val = substr($hex, $offset, $val_len * 2);
        $offset += $val_len * 2;
      }
      $extra_data[$key] = $val;
    }

    [$sign_len, $offset] = VarInt::readUint($hex, $offset);
    $signature = substr($hex, $offset, $sign_len * 2);
    $offset += $sign_len * 2;

    // If isset we did not parse full tx
    // var_dump(isset($hex[$offset]));

    return [
      'id' => static::hexToBase58Check(static::getTxHashHex($hex)),
      'transactor' => $transactor,
      'type_id' => $type_id,
      'inputs' => $inputs,
      'outputs' => $outputs,
      'signature' => $signature,
      'meta' => $meta,
      'extra' => $extra_data,
    ];
  }

  protected static function hexToBase58Check(string $hex): string {
    return Base58Codec::checkEncode('cd1400' . $hex);
  }

  protected static function readString(string $hex, int $offset = 0): array {
    [$len, $offset] = VarInt::readUint($hex, $offset);
    return [substr($hex, $offset, $len * 2), $offset + $len * 2];
  }

  protected static function readInputs(string $hex, int $offset = 0): array {
    $inputs = [];
    [$input_cnt, $offset] = VarInt::readUint($hex, $offset);
    while ($input_cnt-- > 0) {
      $tx_id = substr($hex, $offset, 64);
      $offset += 64;
      [$index, $offset] = VarInt::readUint($hex, $offset);
      $inputs[] = [static::hexToBase58Check($tx_id), $index];
    }
    return [$inputs, $offset];
  }

  protected static function getTxHashHex(string $raw): string {
    return hash('sha256', hash('sha256', hex2bin($raw), true));
  }
}
