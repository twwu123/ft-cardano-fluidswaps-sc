use aiken/builtin
use aiken/cbor
use cardano/address.{Credential}
use cardano/certificate.{Certificate}
use cardano/transaction.{Datum, OutputReference, Transaction}

fn validate_signature_key(publicKey: ByteArray, msg: ByteArray, sig: ByteArray) {
  trace cbor.diagnostic(
    builtin.verify_ecdsa_secp256k1_signature(publicKey, msg, sig),
  )
  builtin.verify_ecdsa_secp256k1_signature(publicKey, msg, sig)
}

// This validator should in theory be able to be used as the "smart accounts".
// It seems extremely straight forward, but since the bitcoin and ethereum accounts are used to
// sign the entire Cardano transaction, it is impossible for someone to use a signature for anything
// that is different from the specifically signed transaction.

// The only fear is that the redeemers are removed from the transaction before signing,
// but the transaction body is signed, so the signer should be convinced of the changes
// that could happen as a result of the transaction being executed.
validator poc_global(pub_key: ByteArray) {
  spend(
    _datum: Option<Datum>,
    redeemer: ByteArray,
    _own_ref: OutputReference,
    self: Transaction,
  ) {
    let message = cbor.serialise(Transaction { ..self, redeemers: [] })
    let signature = redeemer

    validate_signature_key(pub_key, message, signature)
  }

  withdraw(redeemer: ByteArray, _account: Credential, self: Transaction) {
    let message = cbor.serialise(Transaction { ..self, redeemers: [] })
    let signature = redeemer

    validate_signature_key(pub_key, message, signature)
  }

  publish(redeemer: ByteArray, _certificate: Certificate, self: Transaction) {
    let message = cbor.serialise(Transaction { ..self, redeemers: [] })
    let signature = redeemer

    validate_signature_key(pub_key, message, signature)
  }

  else(_) {
    fail
  }
}
