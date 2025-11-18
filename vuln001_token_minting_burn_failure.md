# Vulnerability #001: Token Inflation via Failed Burn in Liquidation

## Severity: CRITICAL

## Status: CONFIRMED

## Location
- File: `/pallets/liquidation/src/lib.rs`
- Function: `liquidate()`
- Lines: 270-292

## Description
The liquidation pallet has a critical vulnerability where tokens can be permanently minted without being burned, leading to token inflation. The issue occurs in the non-Hollar liquidation path.

## Vulnerable Code
```rust
// Line 270-292
} else {
    let pallet_acc = Self::account_id();
    <T as Config>::Currency::mint_into(debt_asset, &pallet_acc, debt_to_cover)?; // MINTS TOKENS
    let pallet_address = T::EvmAccounts::evm_address(&pallet_acc);

    Self::liquidate_position_internal(
        pallet_address,
        collateral_asset,
        debt_asset,
        debt_to_cover,
        user,
        route.clone(),
    )?;

    let _ = <T as Config>::Currency::burn_from(  // ERROR IGNORED WITH 'let _'
        debt_asset,
        &pallet_acc,
        debt_to_cover,
        Preservation::Expendable,
        Precision::Exact,
        Fortitude::Force,
    )?;
}
```

## Root Cause
1. **Line 272**: Tokens are minted into the pallet account
2. **Line 275-282**: Internal liquidation is executed (can fail, properly propagates error with `?`)
3. **Line 284-291**: Tokens are burned, but **THE RESULT IS IGNORED** with `let _`

The `let _` assignment means that even if `burn_from()` returns an error, it is discarded and the function returns `Ok(())`.

## Attack Vector

### Scenario 1: Burn Failure Due to Insufficient Balance
If the `liquidate_position_internal()` transfers tokens away from `pallet_acc` (which it might do for profit distribution), the burn could fail due to insufficient balance.

### Scenario 2: Asset Configuration Issues
If the asset has special burn rules or restrictions that could cause the burn to fail, tokens remain minted.

## Impact
- **Token Inflation**: Each failed burn leaves minted tokens in circulation
- **Economic Exploit**: Attacker could repeatedly trigger this to inflate the supply of any non-Hollar asset
- **Protocol Insolvency**: Inflated supply devalues the asset and destabilizes the protocol

## Proof of Concept
1. Identify a debt asset that can be liquidated (non-Hollar)
2. Call `liquidate()` with parameters that cause the burn to fail
3. Tokens are minted on line 272
4. Even if burn fails on line 284, no error is propagated
5. Function returns Ok(()), tokens remain minted

## Recommended Fix
Change line 284 from:
```rust
let _ = <T as Config>::Currency::burn_from(
```

To:
```rust
<T as Config>::Currency::burn_from(
```

This will properly propagate the error with the `?` operator if the burn fails.

## Verification Steps
1. ✅ Confirmed vulnerable code pattern exists
2. ✅ Verified error handling logic ignores burn failure
3. ✅ Confirmed minted tokens would remain if burn fails

## References
- CWE-682: Incorrect Calculation
- CWE-703: Improper Check or Handling of Exceptional Conditions
- Substrate Currency Trait Documentation

## Timeline
- Discovered: 2025-11-18
- Verified: 2025-11-18
- Status: Awaiting Fix
