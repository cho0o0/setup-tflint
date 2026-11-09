import crypto from 'crypto';
import os from 'os';
import path from 'path';

import { bundleFromJSON } from '@sigstore/bundle';
import { getTrustedRoot } from '@sigstore/tuf';
import { toSignedEntity, toTrustMaterial, Verifier } from '@sigstore/verify';

// TFLint attests checksums.txt from .github/workflows/release.yml, which runs on v*.*.* tag pushes.
// https://github.com/terraform-linters/tflint/blob/master/.github/workflows/release.yml
const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
const IN_TOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const IN_TOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1';
const SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1';

/**
 * @param {Buffer|string} data
 * @returns {string} Hex-encoded SHA256 digest
 */
function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Identity (certificate SAN) of TFLint's release workflow for a given tag.
 * @param {string} version - Release tag (e.g. "v0.61.0")
 * @returns {RegExp}
 */
function signerIdentity(version) {
  // The version is escaped, so it can only match itself literally.
  // eslint-disable-next-line security/detect-non-literal-regexp
  return new RegExp(
    `^https://github\\.com/terraform-linters/tflint/\\.github/workflows/release\\.yml@refs/tags/${escapeRegExp(version)}$`,
  );
}

/**
 * Find the SHA256 of an asset in a checksums.txt file ("<sha256>  <file name>" per line).
 * @param {string} checksumsText
 * @param {string} assetName
 * @returns {string|undefined}
 */
function findChecksum(checksumsText, assetName) {
  for (const line of checksumsText.split(/\r?\n/)) {
    const match = line.trim().match(/^([0-9a-f]{64})\s+\*?(\S+)$/);
    if (match && match[2] === assetName) {
      return match[1];
    }
  }

  return undefined;
}

/**
 * Check that an in-toto statement is SLSA provenance for the given SHA256 digest.
 * @param {object} statement
 * @param {string} digest
 */
function verifyStatement(statement, digest) {
  if (statement?._type !== IN_TOTO_STATEMENT_V1) {
    throw new Error(`unexpected statement type ${statement?._type}`);
  }

  if (statement.predicateType !== SLSA_PROVENANCE_V1) {
    throw new Error(`unexpected predicate type ${statement.predicateType}`);
  }

  const subjects = Array.isArray(statement.subject) ? statement.subject : [];
  if (!subjects.some((subject) => subject?.digest?.sha256 === digest)) {
    throw new Error(`statement does not cover sha256:${digest}`);
  }
}

async function loadTrustMaterial() {
  // Sigstore public-good trust root, fetched and verified through TUF.
  const cachePath = path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'setup-tflint-sigstore');
  const trustedRoot = await getTrustedRoot({ cachePath });
  return toTrustMaterial(trustedRoot);
}

/**
 * Verify that checksums.txt was attested by TFLint's release workflow for this version.
 * Throws unless at least one attestation passes every check.
 * @param {object} params
 * @param {import('@octokit/rest').Octokit} params.octokit
 * @param {string} params.version - Release tag (e.g. "v0.61.0")
 * @param {Buffer} params.checksums - Contents of checksums.txt
 * @param {() => Promise<object>} [params.getTrustMaterial] - Override for tests
 */
async function verifyChecksumsAttestation({
  octokit,
  version,
  checksums,
  getTrustMaterial = loadTrustMaterial,
}) {
  const digest = sha256(checksums);
  let attestations;

  try {
    const { data } = await octokit.request(
      'GET /repos/{owner}/{repo}/attestations/{subject_digest}',
      {
        owner: 'terraform-linters',
        repo: 'tflint',
        subject_digest: `sha256:${digest}`,
      },
    );
    attestations = data?.attestations || [];
  } catch (error) {
    // The API answers 404 when nothing is attested for the digest.
    if (error.status !== 404) {
      throw error;
    }

    attestations = [];
  }
  if (attestations.length === 0) {
    throw new Error(
      `No attestations found for checksums.txt (sha256:${digest}) of TFLint ${version}. ` +
        "Releases before v0.51.1 have no attestation; set verify_attestation to 'false' to install them.",
    );
  }

  const verifier = new Verifier(await getTrustMaterial());
  const policy = {
    subjectAlternativeName: signerIdentity(version),
    extensions: { issuer: OIDC_ISSUER },
  };

  const failures = [];
  for (const attestation of attestations) {
    try {
      if (!attestation.bundle) {
        throw new Error('attestation has no bundle');
      }

      const bundle = bundleFromJSON(attestation.bundle);
      if (bundle.content.$case !== 'dsseEnvelope') {
        throw new Error('attestation is not a DSSE envelope');
      }

      const envelope = bundle.content.dsseEnvelope;
      if (envelope.payloadType !== IN_TOTO_PAYLOAD_TYPE) {
        throw new Error(`unexpected payload type ${envelope.payloadType}`);
      }

      // Checks the signature, the certificate chain to Fulcio, the transparency log entry,
      // and that the signer is TFLint's release workflow on this tag.
      verifier.verify(toSignedEntity(bundle), policy);
      verifyStatement(JSON.parse(envelope.payload.toString('utf8')), digest);
      return;
    } catch (error) {
      failures.push(error.message);
    }
  }

  throw new Error(
    `No attestation for checksums.txt of TFLint ${version} was signed by terraform-linters/tflint's release workflow: ${failures.join('; ')}`,
  );
}

export { findChecksum, sha256, signerIdentity, verifyChecksumsAttestation, verifyStatement };
