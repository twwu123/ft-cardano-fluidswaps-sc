use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{keccak_256, sha2_256}
use aiken/interval.{Finite}
use aiken/primitive/bytearray.{length}
use aiken/primitive/int.{to_string}
use aiken/primitive/string
use cardano/transaction.{OutputReference, Transaction}
use constants
use redeemer.{Cancel, Claim, SwapRedeemer}

validator swap(
  hashed_password: ByteArray,
  owner_ada_pubkey_hash: ByteArray,
  _owner_external_chain_pubkey: ByteArray,
  deadline: Int,
  external_user_chain_pubkey: ByteArray,
) {
  spend(
    _datum: Option<Data>,
    redeemer: SwapRedeemer,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    when redeemer is {
      Claim(preimage, signature) -> {
        let message_hash_btc = get_hash_from_bytearray_btc(preimage)
        let message_hash_eth = get_hash_from_bytearray_eth(preimage)
        expect sha2_256(preimage) == hashed_password
        expect or {
            validate_signature_key(
              external_user_chain_pubkey,
              message_hash_btc,
              signature,
            ),
            validate_signature_key(
              external_user_chain_pubkey,
              message_hash_eth,
              signature,
            ),
          }

        True
      }
      Cancel -> {
        expect validate_tx_end(self, deadline) == True
        list.has(self.extra_signatories, owner_ada_pubkey_hash)
      }
    }
  }

  else(_) {
    fail
  }
}

pub fn validate_tx_end(tx: Transaction, deadline: Int) {
  trace cbor.diagnostic(deadline)
  when tx.validity_range.upper_bound.bound_type is {
    Finite(end) -> end < deadline
    _ -> False
  }
}

pub fn get_hash_from_bytearray_btc(byte: ByteArray) {
  //this is what I sign
  let concat_message =
    string.to_bytearray(bytearray.to_hex(sha2_256(sha2_256(byte))))
  let size = length(concat_message)

  //il doppio sha poi lo rendo stringa e maiuscolo, è quello che firmo
  let final_message =
    bytearray.concat(bytearray.from_int_big_endian(size, 1), concat_message)

  let magic_array = bytearray.from_string(constants.magic_btc)
  let final_magic = bytearray.concat(#"18", magic_array)

  let finalized = bytearray.concat(final_magic, final_message)

  sha2_256(sha2_256(finalized))
}

pub fn get_hash_from_bytearray_eth(byte: ByteArray) {
  //this is what I sign
  let concat_message =
    string.to_bytearray(bytearray.to_hex(sha2_256(sha2_256(byte))))
  let size = string.to_bytearray(to_string(length(concat_message)))

  //il doppio sha poi lo rendo stringa e maiuscolo, è quello che firmo
  let final_message = bytearray.concat(size, concat_message)

  let magic_array = bytearray.from_string(constants.magic_eth)
  let final_magic = bytearray.concat(#"19", magic_array)

  let finalized = bytearray.concat(final_magic, final_message)

  keccak_256(finalized)
}

pub fn validate_signature_key(
  publicKey: ByteArray,
  msg: ByteArray,
  sig: ByteArray,
) {
  builtin.verify_ecdsa_secp256k1_signature(publicKey, msg, sig)
}
