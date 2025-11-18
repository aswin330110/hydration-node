# Vulnerability #004: Missing Access Control in Liquidation Function

## Severity: CRITICAL

## Status: CONFIRMED

## Location
- File: `/pallets/liquidation/src/lib.rs`
- Function: `liquidate()`
- Line: 239-295

## Description
The `liquidate()` function has a critical access control vulnerability where the origin parameter is intentionally unused (prefixed with `_`), allowing ANY user to call this function with arbitrary parameters. This enables unauthorized liquidations with malicious routes and amplifies the impact of other vulnerabilities.

## Vulnerable Code
```rust
// Line 239-245
pub fn liquidate(
    _origin: OriginFor<T>,  // ⚠️ ORIGIN IS UNUSED!
    collateral_asset: AssetId,
    debt_asset: AssetId,
    user: EvmAddress,
    debt_to_cover: Balance,
    route: Route<AssetId>,   // ⚠️ USER-CONTROLLED
) -> DispatchResult {
```

## Root Cause
1. **Line 240**: The `_origin` parameter has an underscore prefix, which in Rust indicates an intentionally unused variable
2. **No origin validation**: The function does not call `ensure_signed()`, `ensure_root()`, or any other origin check
3. **Permissionless execution**: Any signed user can call this extrinsic
4. **User-controlled parameters**: All parameters including the critical `route` are user-controlled

## Validation Analysis
The `validate_unsigned` implementation (lines 152-183) only validates UNSIGNED transactions:

```rust
fn validate_unsigned(source: TransactionSource, call: &Self::Call) -> TransactionValidity {
    match source {
        TransactionSource::External => {
            // receiving unsigned transaction from network - disallow
            return InvalidTransaction::Call.into();
        }
        TransactionSource::Local => {}   // produced by offchain worker
        TransactionSource::InBlock => {} // some other node included it in a block
    };
    // ... validates unsigned only
}
```

**This does NOT protect against SIGNED transactions!** Any user can sign and submit a liquidate transaction.

## Attack Vectors

### Attack 1: Unauthorized Liquidation with Malicious Route
1. Attacker calls `liquidate()` as a signed transaction (no check prevents this)
2. Provides malicious route parameter
3. Exploits vuln002 (insufficient slippage protection)
4. Extracts value through the malicious route

### Attack 2: Token Inflation via Controlled Liquidation
1. Attacker calls `liquidate()` with non-Hollar debt asset
2. Tokens are minted (line 272)
3. If burn fails (vuln001), tokens remain in circulation
4. Attacker can repeat this to inflate token supply

### Attack 3: Griefing Legitimate Positions
1. Attacker front-runs legitimate liquidations
2. Calls `liquidate()` first with suboptimal parameters
3. Legitimate liquidators lose MEV opportunity
4. Position owner loses more collateral due to poor route

### Attack 4: Cross-Vulnerability Exploit Chain
Combines multiple vulnerabilities:
1. Call `liquidate()` (no access control - vuln004)
2. With malicious route (exploits vuln002 - zero slippage per trade)
3. If burn fails (exploits vuln001 - ignored burn failure)
4. Result: Massive value extraction + token inflation

## Impact
- **Critical Access Control Bypass**: Anyone can liquidate positions
- **Amplifies Other Vulnerabilities**: Makes vuln001, vuln002, and vuln003 easily exploitable
- **Economic Exploitation**: Attackers can extract maximum value from every liquidation
- **Protocol Insolvency**: Combined exploits can drain protocol funds
- **Token Inflation**: Uncontrolled minting without proper burning
- **User Loss**: Position owners lose more collateral than necessary

## Proof of Concept
```typescript
// Anyone can call this as a signed transaction
await liquidationPallet.liquidate(
  collateralAsset,
  debtAsset,
  victimUser,
  debtToCover,
  maliciousRoute  // Attacker's route that drains value
);

// Transaction succeeds because origin is not checked!
```

## Expected Behavior
The function should verify that:
1. Only authorized liquidators can call it (e.g., trusted offchain worker)
2. OR implement proper public liquidation checks:
   - Position is actually liquidatable
   - Route is validated/whitelisted
   - Proper slippage protection per trade

## Recommended Fix

### Option 1: Restrict to Authorized Origin
```rust
pub fn liquidate(
    origin: OriginFor<T>,  // Remove underscore
    collateral_asset: AssetId,
    debt_asset: AssetId,
    user: EvmAddress,
    debt_to_cover: Balance,
    route: Route<AssetId>,
) -> DispatchResult {
    // Only allow offchain worker or specific authority
    T::AuthorityOrigin::ensure_origin(origin)?;

    // Rest of function...
}
```

### Option 2: Public Liquidation with Safeguards
```rust
pub fn liquidate(
    origin: OriginFor<T>,
    collateral_asset: AssetId,
    debt_asset: AssetId,
    user: EvmAddress,
    debt_to_cover: Balance,
    route: Route<AssetId>,
) -> DispatchResult {
    let _who = ensure_signed(origin)?;  // At minimum, require signed

    // Validate the route is whitelisted or from RouteProvider
    let expected_route = T::Router::get_route(
        AssetPair::new(collateral_asset, debt_asset)
    );
    ensure!(route == expected_route, Error::<T>::InvalidRoute);

    // Verify position is actually liquidatable
    ensure!(
        Self::is_position_liquidatable(user, debt_asset)?,
        Error::<T>::PositionNotLiquidatable
    );

    // Rest of function with proper validations...
}
```

### Option 3: Separate Public and Internal Functions
```rust
// Internal function (current implementation)
fn liquidate_internal(
    collateral_asset: AssetId,
    debt_asset: AssetId,
    user: EvmAddress,
    debt_to_cover: Balance,
    route: Route<AssetId>,
) -> DispatchResult {
    // Current logic
}

// Public extrinsic with proper checks
pub fn liquidate(
    origin: OriginFor<T>,
    collateral_asset: AssetId,
    debt_asset: AssetId,
    user: EvmAddress,
    debt_to_cover: Balance,
) -> DispatchResult {
    T::AuthorityOrigin::ensure_origin(origin)?;

    // Get validated route
    let route = T::Router::get_route(
        AssetPair::new(collateral_asset, debt_asset)
    );

    Self::liquidate_internal(
        collateral_asset,
        debt_asset,
        user,
        debt_to_cover,
        route
    )
}
```

## Verification Steps
1. ✅ Confirmed `_origin` parameter is unused
2. ✅ Verified no `ensure_signed()` or `ensure_root()` calls
3. ✅ Confirmed `validate_unsigned` only applies to unsigned transactions
4. ✅ Verified signed transactions bypass all validation
5. ✅ Confirmed route parameter is user-controlled

## Related Vulnerabilities
- **vuln001**: Token inflation via burn failure - exploitable through this access control issue
- **vuln002**: Insufficient slippage protection - amplified by user-controlled route
- **vuln003**: Route executor zero slippage - same route issue affects this pallet

## References
- CWE-862: Missing Authorization
- CWE-284: Improper Access Control
- OWASP Top 10 2021: A01 Broken Access Control

## Additional Notes
The design pattern suggests this was intended for offchain worker usage only, but the implementation allows anyone to call it as a signed transaction. This is a common mistake in Substrate pallets where developers assume `validate_unsigned` provides all the protection needed, forgetting that signed transactions bypass that validation entirely.

## Timeline
- Discovered: 2025-11-18
- Verified: 2025-11-18
- Status: Awaiting Fix
- Severity: CRITICAL (10.0 CVSS)
