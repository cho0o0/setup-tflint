import crypto from 'crypto';

import { jest } from '@jest/globals';

const bundleFromJSON = jest.fn();
const toSignedEntity = jest.fn((bundle) => ({ entityOf: bundle }));
const verify = jest.fn();
const Verifier = jest.fn(() => ({ verify }));

jest.unstable_mockModule('@sigstore/bundle', () => ({ bundleFromJSON }));
jest.unstable_mockModule('@sigstore/tuf', () => ({ getTrustedRoot: jest.fn() }));
jest.unstable_mockModule('@sigstore/verify', () => ({
  toSignedEntity,
  toTrustMaterial: jest.fn(),
  Verifier,
}));

const { findChecksum, signerIdentity, verifyChecksumsAttestation, verifyStatement } = await import(
  './attestation.js'
);

// From https://github.com/terraform-linters/tflint/releases/download/v0.61.0/checksums.txt
const CHECKSUMS_V0_61_0 = `9cd3106c7b74f83cbcd90e0593dfaa1ce14dc5260fe32d946915fd0004aec2f4  tflint_darwin_amd64.zip
6593fa24cb6e14d2d0cf7af7fd02a271242f1038af6ecb5384f6738e105a0fea  tflint_darwin_arm64.zip
f8f12c75635cbdf8ff8d3456c5b4d00ac19eebe49a91d4ab7bac4b5252d555c4  tflint_linux_386.zip
`;
const CHECKSUMS = Buffer.from(CHECKSUMS_V0_61_0);
const DIGEST = crypto.createHash('sha256').update(CHECKSUMS).digest('hex');

const statement = (overrides = {}) => ({
  _type: 'https://in-toto.io/Statement/v1',
  subject: [{ name: 'checksums.txt', digest: { sha256: DIGEST } }],
  predicateType: 'https://slsa.dev/provenance/v1',
  predicate: {},
  ...overrides,
});

const dsseBundle = (payload, payloadType = 'application/vnd.in-toto+json') => ({
  content: {
    $case: 'dsseEnvelope',
    dsseEnvelope: { payloadType, payload: Buffer.from(JSON.stringify(payload)) },
  },
});

const request = jest.fn();
const octokit = { request };
const getTrustMaterial = jest.fn(async () => 'trust material');

const run = () =>
  verifyChecksumsAttestation({
    octokit,
    version: 'v0.61.0',
    checksums: CHECKSUMS,
    getTrustMaterial,
  });

beforeEach(() => {
  jest.clearAllMocks();
  request.mockResolvedValue({ data: { attestations: [{ bundle: { json: 'bundle' } }] } });
  bundleFromJSON.mockReturnValue(dsseBundle(statement()));
  verify.mockReturnValue({});
});

describe('findChecksum', () => {
  it('returns the checksum listed for the asset', () => {
    expect(findChecksum(CHECKSUMS_V0_61_0, 'tflint_darwin_arm64.zip')).toBe(
      '6593fa24cb6e14d2d0cf7af7fd02a271242f1038af6ecb5384f6738e105a0fea',
    );
  });

  it('returns undefined for an asset that is not listed', () => {
    expect(findChecksum(CHECKSUMS_V0_61_0, 'tflint_linux_amd64.zip')).toBeUndefined();
  });

  it('does not match a file name that only contains the asset name', () => {
    const text = `${'a'.repeat(64)}  evil_tflint_darwin_arm64.zip\n`;
    expect(findChecksum(text, 'tflint_darwin_arm64.zip')).toBeUndefined();
  });
});

describe('signerIdentity', () => {
  const identity = signerIdentity('v0.61.0');

  it("matches TFLint's release workflow on the tag", () => {
    expect(
      identity.test(
        'https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v0.61.0',
      ),
    ).toBe(true);
  });

  it.each([
    [
      'another tag',
      'https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v0.60.0',
    ],
    [
      'a longer tag',
      'https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v0.61.01',
    ],
    [
      'a dot wildcard',
      'https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v0x61x0',
    ],
    [
      'a branch',
      'https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/heads/master',
    ],
    [
      'another workflow',
      'https://github.com/terraform-linters/tflint/.github/workflows/build.yml@refs/tags/v0.61.0',
    ],
    [
      'another repository',
      'https://github.com/evil/tflint/.github/workflows/release.yml@refs/tags/v0.61.0',
    ],
    [
      'a look-alike repository',
      'https://github.com/terraform-linters/tflint-evil/.github/workflows/release.yml@refs/tags/v0.61.0',
    ],
  ])('rejects %s', (_label, san) => {
    expect(identity.test(san)).toBe(false);
  });
});

describe('verifyStatement', () => {
  it('accepts SLSA provenance for the digest', () => {
    expect(() => verifyStatement(statement(), DIGEST)).not.toThrow();
  });

  it('rejects another predicate type', () => {
    expect(() =>
      verifyStatement(statement({ predicateType: 'https://example.com/other' }), DIGEST),
    ).toThrow('unexpected predicate type');
  });

  it('rejects another statement type', () => {
    expect(() => verifyStatement(statement({ _type: 'other' }), DIGEST)).toThrow(
      'unexpected statement type',
    );
  });

  it('rejects a statement about another digest', () => {
    expect(() => verifyStatement(statement(), 'b'.repeat(64))).toThrow('does not cover');
  });
});

describe('verifyChecksumsAttestation', () => {
  it('looks up attestations for the digest of checksums.txt', async () => {
    await run();

    expect(request).toHaveBeenCalledWith(
      'GET /repos/{owner}/{repo}/attestations/{subject_digest}',
      { owner: 'terraform-linters', repo: 'tflint', subject_digest: `sha256:${DIGEST}` },
    );
  });

  it("requires TFLint's release workflow as the signer", async () => {
    await run();

    expect(Verifier).toHaveBeenCalledWith('trust material');
    const [, policy] = verify.mock.calls[0];
    expect(policy.extensions).toEqual({ issuer: 'https://token.actions.githubusercontent.com' });
    expect(policy.subjectAlternativeName).toEqual(signerIdentity('v0.61.0'));
  });

  it('fails when there are no attestations', async () => {
    request.mockResolvedValue({ data: { attestations: [] } });

    await expect(run()).rejects.toThrow('No attestations found');
  });

  it('fails when the signature or signer does not verify', async () => {
    verify.mockImplementation(() => {
      throw new Error('certificate identity error');
    });

    await expect(run()).rejects.toThrow('certificate identity error');
  });

  it('fails when the statement is about another file', async () => {
    bundleFromJSON.mockReturnValue(
      dsseBundle(statement({ subject: [{ digest: { sha256: 'c'.repeat(64) } }] })),
    );

    await expect(run()).rejects.toThrow('does not cover');
  });

  it('fails when the payload is not an in-toto statement', async () => {
    bundleFromJSON.mockReturnValue(dsseBundle(statement(), 'text/plain'));

    await expect(run()).rejects.toThrow('unexpected payload type');
    expect(verify).not.toHaveBeenCalled();
  });

  it('fails when the bundle is not a DSSE envelope', async () => {
    bundleFromJSON.mockReturnValue({ content: { $case: 'messageSignature' } });

    await expect(run()).rejects.toThrow('not a DSSE envelope');
  });

  it('passes when any attestation verifies', async () => {
    request.mockResolvedValue({
      data: { attestations: [{ bundle: { json: 'bad' } }, { bundle: { json: 'good' } }] },
    });
    verify
      .mockImplementationOnce(() => {
        throw new Error('untrusted signer');
      })
      .mockReturnValueOnce({});

    await expect(run()).resolves.toBeUndefined();
  });
});
