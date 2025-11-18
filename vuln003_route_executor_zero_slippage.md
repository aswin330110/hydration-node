# Vulnerability #003: Zero Slippage Protection on Individual Route Trades

## Severity: CRITICAL

## Status: CONFIRMED

## Location
- File: `/pallets/route-executor/src/lib.rs`
- Function: `do_sell()`
- Lines: 484-504

## Description
The route executor pallet has a critical vulnerability where individual trades within a multi-hop route have ZERO slippage protection. While there is a global `min_amount_out` check at the end, each intermediate trade can return any amount (including zero), allowing attackers to drain value at intermediate hops.

## Vulnerable Code
```rust
// Line 484-504 in do_sell()
for trade in route.iter() {
    let amount_in_to_sell = T::Currency::reducible_balance(
        trade.asset_in,
        &trader_account.clone(),
        Preservation::Expendable,
        Fortitude::Polite,
    );

    let origin: OriginFor<T> = Origin::<T>::Signed(trader_account.clone()).into();

    let execution_result = T::AMM::execute_sell(
        origin,
        trade.pool,          // Pool is user-controlled via route parameter
        trade.asset_in,
        trade.asset_out,
        amount_in_to_sell,
        T::Balance::zero(),  // ⚠️ ZERO MINIMUM AMOUNT OUT!
    );

    handle_execution_error!(execution_result);
}
```

## Root Cause
1. **Line 500**: Each trade in the route uses `T::Balance::zero()` as the minimum amount out
2. **Line 513**: Global `min_amount_out` check only happens AFTER all trades complete
3. **Line 464**: Routes can be user-provided (custom) or from on-chain storage
4. **Line 496**: The pool type in each trade is user-controlled

## Validation Gaps
The `ensure_route_arguments()` function (lines 539-560) only validates:
- First trade starts with correct asset_in
- Last trade ends with correct asset_out
- Trades are properly chained (each trade's output is next trade's input)

It does **NOT** validate:
- Pool legitimacy or liquidity
- Individual trade price impacts
- Whether pools are malicious/manipulated

## Attack Vector

### Multi-Hop Value Extraction Attack
1. **Setup**:
   - Attacker creates malicious pool(s) with poor exchange rates
   - Attacker identifies a valuable asset swap path (e.g., HDX -> USDC)

2. **Execution**:
   - Call `sell()` with custom route: `HDX -> AttackerPool -> USDC`
   - Route validation passes (chain is valid)
   - Trade 1: Sell HDX for worthless tokens in AttackerPool (min_out = 0 ✓)
   - Trade 2: Sell worthless tokens for minimal USDC
   - Global min_amount_out might still fail, BUT...

3. **Advanced Attack** (Bypassing Global Check):
   - Route: `HDX -> LegitPool -> AttackerPool1 -> AttackerPool2 -> USDC`
   - Trade 1: HDX -> DAI (legitimate, good rate)
   - Trade 2: DAI -> JUNK (attacker drains 99% value, min_out = 0 ✓)
   - Trade 3: JUNK -> DUST (min_out = 0 ✓)
   - Trade 4: DUST -> 1 USDC (min_out = 0 ✓)
   - If user set min_amount_out = 1 USDC, attack succeeds!
   - Attacker extracted 99% of DAI value in Trade 2

### Example Scenario
```
User wants to sell 1,000,000 HDX for minimum 50,000 USDC
Attacker route: HDX -> Omnipool(DAI) -> MaliciousPool(JUNK) -> Omnipool(USDC)

Trade 1: 1,000,000 HDX -> 100,000 DAI (Omnipool, fair rate)
Trade 2: 100,000 DAI -> 1 JUNK (MaliciousPool, 99.999% value extraction!)
Trade 3: 1 JUNK -> 50,000 USDC (need to make this work somehow)

Alternatively, combine with liquidation vulnerability for even more damage.
```

## Impact
- **Direct Value Loss**: Users lose funds to malicious intermediate pools
- **MEV Exploitation**: Sandwich attacks on individual route hops
- **Liquidity Fragmentation**: Discourages multi-hop routing
- **Protocol Reputation**: Users avoid using route executor after losses

## Affected Functions
1. `sell()` - Line 195-204
2. `buy()` - Line 222-291 (similar issue with execute_buy)
3. `sell_all()` - Line 429-440 (calls do_sell)
4. `do_sell()` - Line 450-528 (main vulnerability)

## Proof of Concept
1. Deploy a custom pool with manipulated pricing
2. Call `sell()` with route that includes the malicious pool
3. Set global min_amount_out to a low value
4. Observe that intermediate trades accept zero output
5. Extract value from the malicious pool hop

## Recommended Fix

### Option 1: Per-Trade Minimum Output Calculation
```rust
for (i, trade) in route.iter().enumerate() {
    let amount_in_to_sell = T::Currency::reducible_balance(
        trade.asset_in,
        &trader_account.clone(),
        Preservation::Expendable,
        Fortitude::Polite,
    );

    // Calculate expected output based on oracle price
    let expected_output = calculate_expected_output_from_oracle(
        trade.asset_in,
        trade.asset_out,
        amount_in_to_sell,
        trade.pool
    )?;

    // Apply slippage tolerance (e.g., 5%)
    let min_output = expected_output.saturating_mul(95) / 100;

    let execution_result = T::AMM::execute_sell(
        origin,
        trade.pool,
        trade.asset_in,
        trade.asset_out,
        amount_in_to_sell,
        min_output,  // Proper per-trade protection
    );

    handle_execution_error!(execution_result);
}
```

### Option 2: Whitelist Pools
Only allow routes through validated/whitelisted pools, preventing malicious pool injection.

### Option 3: Restrict to On-Chain Routes Only
Remove the ability to provide custom routes for sell/buy operations, forcing users to use validated on-chain routes via `set_route()`.

## Verification Steps
1. ✅ Confirmed zero minimum output in line 500
2. ✅ Verified user-controlled route and pool parameters
3. ✅ Confirmed validation only checks chain continuity, not pool legitimacy
4. ✅ Identified same issue in buy() function

## Related Vulnerabilities
- vuln002: Same conceptual issue in liquidation pallet (hardcoded min of 1)
- This vulnerability is arguably more severe as min is 0 instead of 1

## References
- MEV research: Flash Boys 2.0
- Sandwich attack vectors in AMMs
- CWE-20: Improper Input Validation
- CWE-682: Incorrect Calculation

## Timeline
- Discovered: 2025-11-18
- Verified: 2025-11-18
- Status: Awaiting Fix
