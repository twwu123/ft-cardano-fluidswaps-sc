## DeltaDefi audit checks

Initial comments

### swap.ak

- Simple atomic swap implementation, small recommendation to put parameterized variables into the datum, not necessary, but reduces the number of addresses that must be tracked by backend later on.

- Incorrectly implemented `validate_tx_end` - the idea should be that the transaction to `Cancel` should only be allowed to be triggered after a deadline. In that case, we should be checking that the transaction's `validity_interval.lower_bound > deadline`, currently we are checking `validity_interval.upper_bound < deadline` which allows the creator of the swap to cancel at any moment BEFORE the deadline, and never after. This is the opposite of what is expected.

- Other than this incorrectly implemented `validate_tx_end` the rest seem correct to me

### global.ak

- Initial gut feeling is that it should be possible to simply sign the transaction body after removing the `script_data_hash`, reducing the complexity of this "smart wallet" massively. Currently, the number of checks required is huge, and any security risks are hard to verify. If we are able to sign the transaction body, the checks can be reduced to a single `validate_signature_key(pubKey, cbor.serialise(self), signature)`. The only problem here is that redeemers will include the signature, and will be part of what the wallet signs -> this means a circular dependency and so it cannot be solved. However, we could instead sign a message that has an empty list of redeemers, since technically the redeemer doesn't affect the user intention (redeemers only include the signature itself), this isn't an issue.

- This may be out of the scope of this Audit, but I have included a proof of concept of an implementation of a validator that could be used as the "smart account".

- Biggest issue I have with the current implementation of the "smart accounts" is that the message appears to be some level of instructions that will be signed by the ethereum / bitcoin keys, but it's very difficult to identify exactly what each subsequent byte means. In particular, the `Send` instruction includes an incredible amount of information, and you have to reason about whether the final transaction accurately represents the signed `Send` instruction.
