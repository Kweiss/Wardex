/**
 * WardexShield - Core Implementation
 *
 * The main Wardex interface. Orchestrates the middleware pipeline,
 * manages state, and produces security verdicts.
 */

import type {
  WardexConfig,
  WardexShield,
  SecurityVerdict,
  SecurityPolicy,
  SecurityStatus,
  TransactionRequest,
  ConversationContext,
  Middleware,
  OutputFilter,
  AuditEntry,
} from './types.js';
import { compose, createMiddlewareContext } from './pipeline.js';
import { createOutputFilter } from './output-filter.js';
import { createContextAnalyzer } from './middleware/context-analyzer.js';
import { transactionDecoder } from './middleware/transaction-decoder.js';
import { createAddressChecker } from './middleware/address-checker.js';
import { createValueAssessor } from './middleware/value-assessor.js';
import { createContractChecker } from './middleware/contract-checker.js';
import { createBehavioralComparator } from './middleware/behavioral-comparator.js';
import { riskAggregator } from './middleware/risk-aggregator.js';
import { policyEngine } from './middleware/policy-engine.js';
import { mergePolicy } from './policy.js';

export function createShield(config: WardexConfig): WardexShield {
  let policy = config.policy;
  let frozen = false;
  let freezeReason = '';
  let evaluationCount = 0;
  let blockCount = 0;
  let advisoryCount = 0;
  let dailyVolumeWei = 0n;
  let dailyVolumeResetDate = new Date().toDateString();
  let signerHealthy = true;
  let lastSignerCheck = 0;
  let intelligenceLastUpdated: string | undefined;

  const auditLog: AuditEntry[] = [];
  const filter = createOutputFilter();
  const customMiddlewares: Middleware[] = [];

  const { middleware: contextAnalyzer } = createContextAnalyzer();
  const valueAssessor = createValueAssessor();
  const { middleware: behavioralComparator } = createBehavioralComparator();

  // Wire intelligence provider into address and contract middleware when configured.
  // The intelligence package is an optional peer dependency - we use dynamic import
  // so that @wardex/core works standalone without @wardex/intelligence installed.
  let addressChecker: Middleware;
  let contractChecker: Middleware;

  if (config.intelligence) {
    // Lazy-load intelligence provider. If @wardex/intelligence isn't installed,
    // fall back to stub middleware with no external reputation lookups.
    try {
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const { createIntelligenceProvider } = require('@wardex/intelligence') as {
        createIntelligenceProvider: (cfg: {
          rpcUrl: string;
          chainId: number;
          denylistPath?: string;
          explorerApiKey?: string;
          explorerApiUrl?: string;
        }) => {
          getAddressReputation: (address: string) => Promise<import('./types.js').AddressReputation>;
          getContractAnalysis: (address: string) => Promise<import('./types.js').ContractAnalysis>;
        };
      };

      const intel = createIntelligenceProvider({
        rpcUrl: config.intelligence.rpcUrl,
        chainId: config.intelligence.chainId,
        denylistPath: config.intelligence.denylistPath,
        explorerApiKey: config.intelligence.explorerApiKey,
        explorerApiUrl: `https://api.etherscan.io/api`,
      });

      addressChecker = createAddressChecker(
        async (address, _chainId) => intel.getAddressReputation(address),
      );
      contractChecker = createContractChecker(
        async (address, _chainId) => intel.getContractAnalysis(address),
      );
    } catch {
      // @wardex/intelligence not installed - use stubs
      addressChecker = createAddressChecker();
      contractChecker = createContractChecker();
    }
  } else {
    addressChecker = createAddressChecker();
    contractChecker = createContractChecker();
  }

  /**
   * Builds the full middleware pipeline.
   */
  function buildPipeline(): Middleware {
    return compose([
      // Core pipeline in order:
      // 1. Analyze conversation context for prompt injection
      contextAnalyzer,
      // 2. Decode transaction calldata (function, params, type)
      transactionDecoder,
      // 3. Calculate USD value at risk (needed for tier determination)
      valueAssessor,
      // 4. Check target address against denylists and reputation
      addressChecker,
      // 5. Analyze contract bytecode for dangerous patterns
      contractChecker,
      // 6. Compare against behavioral baseline (anomaly detection)
      behavioralComparator,
      // 7. Insert any custom operator middlewares
      ...customMiddlewares,
      // 8. Aggregate all risk scores into composite
      riskAggregator,
      // 9. Apply policy rules and produce final verdict
      policyEngine,
    ]);
  }

  /**
   * Resets daily volume counter if the date has changed.
   */
  function checkDailyReset(): void {
    const today = new Date().toDateString();
    if (today !== dailyVolumeResetDate) {
      dailyVolumeWei = 0n;
      dailyVolumeResetDate = today;
    }
  }

  /**
   * Records an evaluation in the audit log.
   */
  function recordAudit(
    tx: TransactionRequest,
    verdict: SecurityVerdict,
    context?: ConversationContext,
    executed?: boolean
  ): void {
    auditLog.push({
      evaluationId: verdict.evaluationId,
      timestamp: verdict.timestamp,
      transaction: tx,
      verdict,
      contextSummary: context
        ? `${context.messages.length} messages, source: ${context.source.identifier}`
        : undefined,
      executed: executed ?? verdict.decision === 'approve',
    });

    // Keep audit log bounded (last 10,000 entries)
    if (auditLog.length > 10_000) {
      auditLog.splice(0, auditLog.length - 10_000);
    }
  }

  /**
   * Core evaluation logic.
   */
  async function evaluateInternal(
    tx: TransactionRequest,
    context?: ConversationContext
  ): Promise<SecurityVerdict> {
    // Check if frozen
    if (frozen) {
      const frozenVerdict: SecurityVerdict = {
        decision: 'freeze',
        riskScore: { context: 0, transaction: 0, behavioral: 0, composite: 100 },
        reasons: [{
          code: 'SYSTEM_FROZEN',
          message: `System is in emergency freeze: ${freezeReason}`,
          severity: 'critical',
          source: 'policy',
        }],
        suggestions: ['Contact operator to unfreeze the system'],
        requiredAction: 'human_approval',
        timestamp: new Date().toISOString(),
        evaluationId: crypto.randomUUID(),
        tierId: 'frozen',
      };
      recordAudit(tx, frozenVerdict, context, false);
      return frozenVerdict;
    }

    checkDailyReset();
    evaluationCount++;

    // Track intelligence activity timestamp
    if (config.intelligence) {
      intelligenceLastUpdated = new Date().toISOString();
    }

    // Build and run the middleware pipeline
    const pipeline = buildPipeline();
    const ctx = createMiddlewareContext({
      transaction: tx,
      conversationContext: context,
      policy,
    });

    await pipeline(ctx, async () => {});

    // Extract verdict from pipeline
    const verdict = ctx.metadata.verdict as SecurityVerdict | undefined;

    if (!verdict) {
      // Pipeline didn't produce a verdict (shouldn't happen with policyEngine)
      const fallbackVerdict: SecurityVerdict = {
        decision: 'block',
        riskScore: { context: 0, transaction: 0, behavioral: 0, composite: 50 },
        reasons: [{
          code: 'PIPELINE_ERROR',
          message: 'Evaluation pipeline did not produce a verdict',
          severity: 'high',
          source: 'policy',
        }],
        suggestions: ['Check Wardex configuration'],
        timestamp: new Date().toISOString(),
        evaluationId: crypto.randomUUID(),
        tierId: 'error',
      };
      recordAudit(tx, fallbackVerdict, context, false);
      return fallbackVerdict;
    }

    // Update counters
    if (verdict.decision === 'block' || verdict.decision === 'freeze') {
      blockCount++;
      config.onBlock?.({ verdict, transaction: tx, decoded: ctx.decoded });
    } else if (verdict.decision === 'advise') {
      advisoryCount++;
      config.onAdvisory?.({ verdict, transaction: tx });
    }

    // Track daily volume for approved transactions
    if (verdict.decision === 'approve') {
      dailyVolumeWei += BigInt(tx.value ?? '0');

      // Check if daily volume exceeds limit
      if (dailyVolumeWei > BigInt(policy.limits.maxDailyVolumeWei)) {
        verdict.decision = 'block';
        verdict.requiredAction = 'human_approval';
        verdict.reasons.push({
          code: 'DAILY_VOLUME_EXCEEDED',
          message: 'Daily transaction volume limit exceeded',
          severity: 'high',
          source: 'policy',
        });
        blockCount++;
      }
    }

    // Record the audit entry BEFORE freeze check so it's included
    recordAudit(tx, verdict, context);

    // Auto-freeze on multiple consecutive blocks (possible active attack)
    if (verdict.decision === 'block' || verdict.decision === 'freeze') {
      const recentEntries = auditLog.slice(-10);
      const recentBlocks = recentEntries.filter(
        (e) => e.verdict.decision === 'block' || e.verdict.decision === 'freeze'
      );

      if (recentBlocks.length >= 5) {
        frozen = true;
        freezeReason = `Auto-freeze: ${recentBlocks.length} blocked transactions in last ${recentEntries.length} evaluations`;
        config.onFreeze?.({
          reason: freezeReason,
          details: `Blocked evaluations: ${recentBlocks.map((e) => e.evaluationId).join(', ')}`,
          timestamp: new Date().toISOString(),
        });
        config.onThreat?.({
          threatType: 'AUTO_FREEZE',
          severity: 'critical',
          details: freezeReason,
        });
      }
    }
    return verdict;
  }

  // Build the shield object
  const shield: WardexShield = {
    async evaluate(tx: TransactionRequest): Promise<SecurityVerdict> {
      return evaluateInternal(tx);
    },

    async evaluateWithContext(
      tx: TransactionRequest,
      context: ConversationContext
    ): Promise<SecurityVerdict> {
      return evaluateInternal(tx, context);
    },

    outputFilter: filter,

    getStatus(): SecurityStatus {
      return {
        mode: config.mode,
        frozen,
        evaluationCount,
        blockCount,
        advisoryCount,
        dailyVolumeWei: dailyVolumeWei.toString(),
        signerHealthy,
        intelligenceLastUpdated,
      };
    },

    updatePolicy(overrides: Partial<SecurityPolicy>): void {
      policy = mergePolicy(policy, overrides);
    },

    getAuditLog(limit?: number): AuditEntry[] {
      if (limit) {
        return auditLog.slice(-limit);
      }
      return [...auditLog];
    },

    use(middleware: Middleware): void {
      customMiddlewares.push(middleware);
    },

    isFrozen(): boolean {
      return frozen;
    },

    freeze(reason: string): void {
      frozen = true;
      freezeReason = reason;
      config.onFreeze?.({
        reason,
        details: 'Manual freeze triggered',
        timestamp: new Date().toISOString(),
      });
    },

    unfreeze(): void {
      frozen = false;
      freezeReason = '';
    },
  };

  return shield;
}
