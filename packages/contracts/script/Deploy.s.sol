// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WardexValidationModule} from "../src/WardexValidationModule.sol";

/**
 * @title Deploy
 * @notice Deploys WardexValidationModule to any EVM chain.
 *
 * Usage (testnet):
 *   forge script script/Deploy.s.sol \
 *     --rpc-url $BASE_SEPOLIA_RPC \
 *     --private-key $DEPLOYER_PK \
 *     --broadcast \
 *     --verify \
 *     --etherscan-api-key $ETHERSCAN_KEY
 *
 * Usage (dry-run, no broadcast):
 *   forge script script/Deploy.s.sol --rpc-url $RPC_URL
 *
 * After deployment, call initialize() from your smart account to enable
 * Wardex protection with your evaluator address and spending limits.
 */
contract Deploy is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envOr("DEPLOYER_PK", uint256(0));

        // If no PK, do a simulation run
        if (deployerPrivateKey == 0) {
            console.log("No DEPLOYER_PK set - running simulation");
            vm.startBroadcast();
        } else {
            vm.startBroadcast(deployerPrivateKey);
        }

        WardexValidationModule module = new WardexValidationModule();

        console.log("========================================");
        console.log("WardexValidationModule deployed at:", address(module));
        console.log("Chain ID:", block.chainid);
        console.log("========================================");
        console.log("");
        console.log("Next steps:");
        console.log("  1. From your smart account, call:");
        console.log("     module.initialize(evaluatorAddress, ethMaxPerTx, ethMaxPerDay)");
        console.log("  2. Set token-specific limits with:");
        console.log("     module.setSpendingLimit(tokenAddress, maxPerTx, maxPerDay)");
        console.log("  3. Install the module on your ERC-4337 account");

        vm.stopBroadcast();
    }
}
