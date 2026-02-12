// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WardexValidationModule} from "../src/WardexValidationModule.sol";

/**
 * @title Verify
 * @notice Post-deployment verification script.
 *         Exercises the deployed WardexValidationModule on-chain to confirm
 *         initialization, spending limits, freeze/unfreeze, and view functions.
 *
 * Usage:
 *   forge script script/Verify.s.sol \
 *     --rpc-url $BASE_SEPOLIA_RPC \
 *     --private-key $DEPLOYER_PK \
 *     --broadcast \
 *     -vvvv
 *
 * Environment:
 *   MODULE_ADDRESS  - Address of the deployed WardexValidationModule
 *   EVALUATOR       - Evaluator address to use for initialization
 */
contract Verify is Script {
    function run() external {
        address moduleAddr = vm.envAddress("MODULE_ADDRESS");
        address evaluator = vm.envOr("EVALUATOR", address(0x1111111111111111111111111111111111111111));

        WardexValidationModule module = WardexValidationModule(moduleAddr);

        vm.startBroadcast();

        // 1. Initialize
        console.log("--- Step 1: Initialize ---");
        module.initialize(
            evaluator,
            1 ether,    // maxPerTx
            10 ether    // maxPerDay
        );
        require(module.isInitialized(msg.sender), "Init failed");
        require(module.getEvaluator(msg.sender) == evaluator, "Evaluator mismatch");
        console.log("  Initialized with evaluator:", evaluator);

        // 2. Check spending limits
        console.log("--- Step 2: Spending Limits ---");
        bool withinLimit = module.checkSpendingLimit(msg.sender, address(0), 0.5 ether);
        require(withinLimit, "0.5 ETH should be within limits");
        console.log("  0.5 ETH within limits: true");

        bool exceedsLimit = module.checkSpendingLimit(msg.sender, address(0), 2 ether);
        require(!exceedsLimit, "2 ETH should exceed per-tx limit");
        console.log("  2 ETH exceeds per-tx: true");

        // 3. Set token spending limit
        console.log("--- Step 3: Token Limits ---");
        address usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
        module.setSpendingLimit(usdc, 1000e6, 10000e6); // 1K / 10K USDC
        bool usdcOk = module.checkSpendingLimit(msg.sender, usdc, 500e6);
        require(usdcOk, "500 USDC should be within limits");
        console.log("  USDC limits set and verified");

        // 4. Freeze and unfreeze
        console.log("--- Step 4: Freeze/Unfreeze ---");
        module.freeze();
        require(module.isFrozen(msg.sender), "Should be frozen");
        console.log("  Frozen: true");

        module.unfreeze();
        require(!module.isFrozen(msg.sender), "Should be unfrozen");
        console.log("  Unfrozen: true");

        // 5. Update evaluator
        console.log("--- Step 5: Evaluator Update ---");
        address newEvaluator = address(0x2222222222222222222222222222222222222222);
        module.setEvaluator(newEvaluator);
        require(module.getEvaluator(msg.sender) == newEvaluator, "Evaluator not updated");
        console.log("  Evaluator updated to:", newEvaluator);

        vm.stopBroadcast();

        console.log("");
        console.log("========================================");
        console.log("All verification checks PASSED");
        console.log("Module:", moduleAddr);
        console.log("Chain ID:", block.chainid);
        console.log("========================================");
    }
}
