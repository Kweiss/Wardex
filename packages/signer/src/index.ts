/**
 * @wardex/signer
 *
 * Isolated signer implementations for Wardex.
 * Key material never touches the AI agent process.
 */

export {
  SignerServer,
  SignerClient,
  encryptPrivateKey,
  decryptPrivateKey,
  generateApprovalToken,
  verifyApprovalToken,
} from './isolated-process.js';

export type {
  SignerServerConfig,
  SignerClientConfig,
} from './isolated-process.js';

export { SessionManager } from './session-manager.js';

export type {
  SessionKeyConfig,
  SessionKey,
  SessionState,
  SessionValidationResult,
} from './session-manager.js';
