use aiken/builtin
use aiken/cbor
use aiken/crypto.{keccak_256, sha2_256}
use aiken/interval.{
  Finite, Interval, IntervalBound, NegativeInfinity, PositiveInfinity,
}
use cardano/address.{from_script}
use cardano/assets.{from_lovelace}
use cardano/transaction.{
  Input, NoDatum, Output, OutputReference, Redeemer, Spend, Transaction,
  placeholder,
}
use swap.{validate_tx_end}

test test_validate_tx_end() fail {
  let tx =
    Transaction {
      ..placeholder,
      validity_range: Interval {
        lower_bound: IntervalBound {
          bound_type: NegativeInfinity,
          is_inclusive: False,
        },
        upper_bound: IntervalBound {
          bound_type: Finite(999),
          is_inclusive: False,
        },
      },
    }

  // This should fail, because we should only be able to cancel the swap after the deadline has
  // passed. However, currently it succeeds, which is not the expected behaviour.
  // What this passing means is that the initiator of the swap can cancel the swap at any moment
  validate_tx_end(tx, 1000)
}

fn validate_signature_key(publicKey: ByteArray, msg: ByteArray, sig: ByteArray) {
  trace cbor.diagnostic(
    builtin.verify_ecdsa_secp256k1_signature(publicKey, msg, sig),
  )
  builtin.verify_ecdsa_secp256k1_signature(publicKey, msg, sig)
}

test test_signatures() {
  let public_key =
    #"02d299b5c3807011445dc278fd24279ed710e7eddbe1db63a31c2cbb59f8173b5f"
  let redeemer: Redeemer =
    #"b82b1e639271dac186c39023987a2cdb356392452b8fcb2bba966eb98cf699a46c10d35d6f430602e00e829d495bded36b931e577cd5e73b708489af4f6290b5"
  let transaction =
    Transaction {
      ..placeholder,
      inputs: [
        Input {
          output_reference: OutputReference {
            transaction_id: #"643d5c4691a0a2e2980dfad92e4aaec0c3983f521fc652f2b60cb23b13403128",
            output_index: 0,
          },
          output: Output {
            address: from_script(
              #"3648635a134750b9814a12e3ca77efe1fd1a979ce250cd90ecd26dc8",
            ),
            value: from_lovelace(1000000),
            datum: NoDatum,
            reference_script: None,
          },
        },
      ],
      outputs: [
        Output {
          address: from_script(
            #"3648635a134750b9814a12e3ca77efe1fd1a979ce250cd90ecd26dc8",
          ),
          value: from_lovelace(1000000),
          datum: NoDatum,
          reference_script: None,
        },
      ],
      redeemers: [
        Pair(
          Spend(
            OutputReference {
              transaction_id: #"643d5c4691a0a2e2980dfad92e4aaec0c3983f521fc652f2b60cb23b13403128",
              output_index: 0,
            },
          ),
          redeemer,
        ),
      ],
    }

  let message = cbor.serialise(Transaction { ..transaction, redeemers: [] })
  trace message
  let signature =
    #"b82b1e639271dac186c39023987a2cdb356392452b8fcb2bba966eb98cf699a46c10d35d6f430602e00e829d495bded36b931e577cd5e73b708489af4f6290b5"

  let message_hash = keccak_256(message)
  trace message_hash
  let is_valid = validate_signature_key(public_key, message_hash, signature)
  is_valid
}
