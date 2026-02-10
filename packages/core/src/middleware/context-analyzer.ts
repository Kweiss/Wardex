/**
 * Context Analyzer Middleware
 *
 * Analyzes the conversation context that led to a transaction request.
 * Detects prompt injection, coherence violations, escalation patterns,
 * and cross-MCP manipulation.
 *
 * v1: Rule-based pattern matching (deterministic, auditable)
 * v2: Local ML classifier for adaptive detection
 */

import type {
  Middleware,
  MiddlewareContext,
  ConversationContext,
  SecurityReason,
} from '../types.js';

// ---------------------------------------------------------------------------
// Known prompt injection patterns
// ---------------------------------------------------------------------------

const INJECTION_PATTERNS: Array<{
  name: string;
  pattern: RegExp;
  severity: 'medium' | 'high' | 'critical';
  description: string;
}> = [
  {
    name: 'IGNORE_INSTRUCTIONS',
    pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|rules|guidelines|constraints)/i,
    severity: 'critical',
    description: 'Attempt to override system instructions',
  },
  {
    name: 'ROLE_OVERRIDE',
    pattern: /you\s+are\s+(now|actually|really)\s+(a|an|the)\s+/i,
    severity: 'high',
    description: 'Attempt to redefine the AI agent role',
  },
  {
    name: 'SYSTEM_PROMPT_INJECTION',
    pattern: /\[?\s*(system|admin|developer|root)\s*(message|prompt|instruction|override)\s*[\]:]?/i,
    severity: 'critical',
    description: 'Fake system message injection',
  },
  {
    name: 'JAILBREAK_PATTERN',
    pattern: /(DAN|do\s+anything\s+now|developer\s+mode|unrestricted\s+mode)/i,
    severity: 'critical',
    description: 'Known jailbreak technique',
  },
  {
    name: 'BASE64_INSTRUCTION',
    pattern: /(?:execute|run|decode|eval)\s*(?:this|the)?\s*(?:base64|encoded)\s*(?:instruction|command|payload)/i,
    severity: 'high',
    description: 'Attempt to smuggle instructions via encoding',
  },
  {
    name: 'HIDDEN_INSTRUCTION_MARKER',
    pattern: /(?:<!--.*?-->|<\s*(?:script|style)[^>]*>.*?<\/\s*(?:script|style)\s*>)/is,
    severity: 'high',
    description: 'Hidden instructions in HTML/markdown comments',
  },
  {
    name: 'URGENCY_MANIPULATION',
    pattern: /(?:immediately|urgently|right\s+now|emergency|time-sensitive)\s+(?:send|transfer|approve|sign)/i,
    severity: 'medium',
    description: 'Urgency-based social engineering',
  },
  {
    name: 'AUTHORIZATION_CLAIM',
    pattern: /(?:authorized|approved|permitted|allowed)\s+(?:by\s+(?:the\s+)?(?:admin|owner|user|operator))/i,
    severity: 'high',
    description: 'False authorization claim in content',
  },
  {
    name: 'SEED_PHRASE_REQUEST',
    pattern: /(?:share|give|send|tell|show|reveal|display|output|print)\s+(?:me\s+)?(?:your\s+)?(?:seed\s+phrase|mnemonic|private\s+key|secret\s+key|recovery\s+phrase)/i,
    severity: 'critical',
    description: 'Explicit request for key material',
  },
  {
    name: 'REDIRECT_FUNDS',
    pattern: /(?:send|transfer|forward|redirect)\s+(?:all|remaining|the)?\s*(?:funds|tokens|eth|balance|assets)\s+(?:to|into)/i,
    severity: 'high',
    description: 'Broad fund redirection instruction',
  },
];

// ---------------------------------------------------------------------------
// Escalation detection
// ---------------------------------------------------------------------------

interface EscalationTracker {
  recentTransactionValues: Array<{ valueUsd: number; timestamp: number }>;
}

const ESCALATION_WINDOW_MS = 30 * 60 * 1000; // 30 minutes
const ESCALATION_THRESHOLD = 5; // Value must increase 5x within window

/**
 * Checks if transaction values are escalating suspiciously fast.
 */
function detectEscalation(
  tracker: EscalationTracker,
  currentValueUsd: number
): SecurityReason | null {
  const now = Date.now();
  // Clean old entries
  tracker.recentTransactionValues = tracker.recentTransactionValues.filter(
    (t) => now - t.timestamp < ESCALATION_WINDOW_MS
  );

  // Add current
  tracker.recentTransactionValues.push({
    valueUsd: currentValueUsd,
    timestamp: now,
  });

  if (tracker.recentTransactionValues.length < 2) return null;

  const oldest = tracker.recentTransactionValues[0];
  const newest = tracker.recentTransactionValues[tracker.recentTransactionValues.length - 1];

  if (oldest.valueUsd > 0 && newest.valueUsd / oldest.valueUsd >= ESCALATION_THRESHOLD) {
    return {
      code: 'VALUE_ESCALATION',
      message: `Transaction value escalated ${(newest.valueUsd / oldest.valueUsd).toFixed(1)}x within ${Math.round((newest.timestamp - oldest.timestamp) / 60000)} minutes`,
      severity: 'high',
      source: 'context',
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Source trust verification
// ---------------------------------------------------------------------------

function evaluateSource(
  context: ConversationContext
): SecurityReason[] {
  const reasons: SecurityReason[] = [];

  if (context.source.trustLevel === 'untrusted') {
    reasons.push({
      code: 'UNTRUSTED_SOURCE',
      message: `Transaction originated from untrusted source: ${context.source.identifier}`,
      severity: 'critical',
      source: 'context',
    });
  }

  if (context.source.type === 'unknown') {
    reasons.push({
      code: 'UNKNOWN_SOURCE',
      message: 'Transaction source could not be identified',
      severity: 'high',
      source: 'context',
    });
  }

  // Check for cross-MCP manipulation: tool outputs that contain transaction instructions
  if (context.toolCallChain) {
    for (const call of context.toolCallChain) {
      if (call.output) {
        for (const pattern of INJECTION_PATTERNS) {
          if (pattern.pattern.test(call.output)) {
            reasons.push({
              code: 'CROSS_MCP_INJECTION',
              message: `Tool "${call.tool}" output contains suspicious instruction: ${pattern.name}`,
              severity: 'critical',
              source: 'context',
            });
            break;
          }
        }
      }
    }
  }

  return reasons;
}

// ---------------------------------------------------------------------------
// Coherence analysis
// ---------------------------------------------------------------------------

/**
 * Simple coherence check: does the transaction make sense given conversation context?
 * v1 uses keyword overlap heuristic. v2 will use embedding similarity.
 */
function checkCoherence(
  context: ConversationContext
): SecurityReason | null {
  if (!context.messages.length) return null;

  // Extract recent conversation topics (simple keyword extraction)
  const recentMessages = context.messages.slice(-5);
  const conversationText = recentMessages.map((m) => m.content).join(' ').toLowerCase();

  // Check if crypto/transaction-related terms appear in recent conversation
  const cryptoTerms = [
    'send', 'transfer', 'swap', 'trade', 'approve', 'token', 'eth',
    'wallet', 'contract', 'defi', 'uniswap', 'aave', 'pool', 'liquidity',
    'stake', 'bridge', 'mint', 'burn', 'withdraw', 'deposit', 'exchange',
    'price', 'buy', 'sell', 'gas', 'nft', 'erc20', 'erc721',
  ];

  const hasCryptoContext = cryptoTerms.some((term) =>
    conversationText.includes(term)
  );

  if (!hasCryptoContext) {
    return {
      code: 'INCOHERENT_CONTEXT',
      message: 'Transaction request does not match recent conversation context - no crypto-related discussion detected',
      severity: 'medium',
      source: 'context',
    };
  }

  return null;
}

// ---------------------------------------------------------------------------
// Middleware export
// ---------------------------------------------------------------------------

/**
 * Creates the context analyzer middleware.
 * Analyzes conversation context for prompt injection, coherence, and escalation.
 */
export function createContextAnalyzer(): {
  middleware: Middleware;
  escalationTracker: EscalationTracker;
} {
  const escalationTracker: EscalationTracker = {
    recentTransactionValues: [],
  };

  const middleware: Middleware = async (ctx: MiddlewareContext, next) => {
    const config = ctx.policy.contextAnalysis;

    // If no conversation context was provided, we can only do limited analysis
    if (!ctx.conversationContext) {
      await next();
      return;
    }

    // 1. Prompt injection detection
    if (config.enablePromptInjectionDetection) {
      // Scan all message content for injection patterns
      for (const message of ctx.conversationContext.messages) {
        for (const pattern of INJECTION_PATTERNS) {
          // Reset regex state for each test
          pattern.pattern.lastIndex = 0;
          if (pattern.pattern.test(message.content)) {
            ctx.reasons.push({
              code: `INJECTION_${pattern.name}`,
              message: `Prompt injection detected: ${pattern.description}`,
              severity: pattern.severity,
              source: 'context',
            });
          }
        }
      }

      // Also check custom patterns from policy
      for (const customPattern of config.suspiciousPatterns) {
        const regex = new RegExp(customPattern, 'i');
        for (const message of ctx.conversationContext.messages) {
          if (regex.test(message.content)) {
            ctx.reasons.push({
              code: 'CUSTOM_PATTERN_MATCH',
              message: `Custom suspicious pattern matched: ${customPattern}`,
              severity: 'medium',
              source: 'context',
            });
          }
        }
      }
    }

    // 2. Source verification
    if (config.enableSourceVerification) {
      const sourceReasons = evaluateSource(ctx.conversationContext);
      ctx.reasons.push(...sourceReasons);
    }

    // 3. Coherence checking
    if (config.enableCoherenceChecking) {
      const coherenceReason = checkCoherence(ctx.conversationContext);
      if (coherenceReason) {
        ctx.reasons.push(coherenceReason);
      }
    }

    // 4. Escalation detection
    if (config.enableEscalationDetection && ctx.decoded) {
      const escalationReason = detectEscalation(
        escalationTracker,
        ctx.decoded.estimatedValueUsd
      );
      if (escalationReason) {
        ctx.reasons.push(escalationReason);
      }
    }

    // Calculate context risk score
    const contextReasons = ctx.reasons.filter((r) => r.source === 'context');
    let contextScore = 0;

    for (const reason of contextReasons) {
      switch (reason.severity) {
        case 'critical':
          contextScore += 40;
          break;
        case 'high':
          contextScore += 25;
          break;
        case 'medium':
          contextScore += 15;
          break;
        case 'low':
          contextScore += 5;
          break;
        case 'info':
          contextScore += 0;
          break;
      }
    }

    ctx.riskScores.context = Math.min(100, contextScore);

    await next();
  };

  return { middleware, escalationTracker };
}
