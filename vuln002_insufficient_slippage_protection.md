# Vulnerability #002: Insufficient Slippage Protection in Liquidation Swap

## Severity: HIGH

## Status: CONFIRMED

## Location
- File: `/pallets/liquidation/src/lib.rs`
- Function: `liquidate_position_internal()`
- Lines: 362-378

## Description
The liquidation pallet uses a hardcoded minimum amount of `1` when swapping liquidated collateral for debt tokens. This effectively provides no slippage protection and can be exploited to drain collateral assets.

## Vulnerable Code
```rust
// Line 362-378
if collateral_asset != debt_asset {
    let collateral_earned = <T as Config>::Currency::balance(collateral_asset, &liquidator_account)
        .checked_sub(collateral_original_balance)
        .defensive_ok_or(ArithmeticError::Underflow)?;

    log::trace!(target: "liquidation",
        "Collateral earned: {:?} for asset: {:?}", collateral_earned, collateral_asset);

    T::Router::sell(
        RawOrigin::Signed(liquidator_account.clone()).into(),
        collateral_asset,
        debt_asset,
        collateral_earned,
        1,  // ⚠️ HARDCODED MINIMUM AMOUNT OUT = 1
        route,
    )?;
}
```

## Root Cause
**Line 375**: The `min_amount_out` parameter is hardcoded to `1`, meaning the swap will accept any output amount greater than or equal to 1 unit of the debt asset, regardless of the input amount.

## Attack Vector

### Attack Scenario
1. **Setup**: Attacker identifies a liquidatable position with valuable collateral
2. **Route Manipulation**: Attacker provides a malicious route parameter that routes through:
   - A low-liquidity pool they control
   - Multiple hops with poor exchange rates
   - A pool they can manipulate just before the liquidation
3. **Execution**: Call `liquidate()` with the malicious route
4. **Result**:
   - Large amount of valuable collateral is swapped
   - Receives only 1 (or very few) units of debt asset
   - Profit check may still pass if liquidation itself provided enough debt tokens

### Example Exploit
```
Collateral Earned: 1,000,000 USDC (worth $1,000,000)
Route: USDC -> AttackerPool -> JUNK -> HDX
Min Amount Out: 1 HDX
Actual Received: 1 HDX (worth ~$0.0001)
Value Lost: ~$999,999.9999
```

## Impact
- **Massive Value Extraction**: Entire collateral value can be extracted for minimal cost
- **Liquidation Inefficiency**: Liquidations become unprofitable for honest actors
- **Protocol Insolvency**: Bad debt accumulates as liquidations don't recover sufficient value
- **MEV Opportunity**: Creates extractable value for malicious liquidators

## Additional Risk Factors
The route parameter is user-controlled (line 245 in `liquidate()` function), making this even more dangerous:
```rust
pub fn liquidate(
    _origin: OriginFor<T>,
    collateral_asset: AssetId,
    debt_asset: AssetId,
    user: EvmAddress,
    debt_to_cover: Balance,
    route: Route<AssetId>,  // ⚠️ USER-CONTROLLED
) -> DispatchResult {
```

## Proof of Concept
1. Create a position that can be liquidated
2. Create a malicious liquidity pool with poor exchange rate
3. Call `liquidate()` with a route that goes through the malicious pool
4. Verify that collateral is swapped for minimal output
5. Profit calculation may still succeed if liquidation bonus is sufficient

## Recommended Fix

### Option 1: Calculate Minimum Based on Oracle Price
```rust
let min_amount_out = calculate_min_output_from_oracle(
    collateral_asset,
    debt_asset,
    collateral_earned,
    acceptable_slippage_percent  // e.g., 5%
)?;

T::Router::sell(
    RawOrigin::Signed(liquidator_account.clone()).into(),
    collateral_asset,
    debt_asset,
    collateral_earned,
    min_amount_out,  // Calculated based on oracle price
    route,
)?;
```

### Option 2: Validate Route Before Execution
```rust
// Ensure route matches expected route from RouterProvider
let expected_route = T::Router::get_route(collateral_asset, debt_asset)?;
ensure!(route == expected_route, Error::<T>::InvalidRoute);
```

### Option 3: Combine Both Approaches
Use a validated route AND calculate proper minimum output based on oracle price with acceptable slippage.

## Verification Steps
1. ✅ Confirmed hardcoded minimum of 1
2. ✅ Verified route parameter is user-controlled
3. ✅ Confirmed no validation of route or output amount

## References
- Similar to "sandwich attack" vulnerabilities in DeFi
- CWE-682: Incorrect Calculation
- CWE-20: Improper Input Validation

## Related Code
- Route validation check exists on line 204 but is not used in this path
- `InvalidRoute` error is defined but never thrown in liquidation flow

## Timeline
- Discovered: 2025-11-18
- Verified: 2025-11-18
- Status: Awaiting Fix
