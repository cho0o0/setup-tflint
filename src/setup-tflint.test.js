import { jest } from '@jest/globals';

const inputs = {};
const core = {
  getInput: jest.fn((name) => inputs[name] || ''),
  getMultilineInput: jest.fn(() => []),
  info: jest.fn(),
  debug: jest.fn(),
  warning: jest.fn(),
  error: jest.fn(),
  setOutput: jest.fn(),
  addPath: jest.fn(),
  exportVariable: jest.fn(),
};
const tc = {
  downloadTool: jest.fn(),
  extractZip: jest.fn(),
  find: jest.fn(),
  cacheDir: jest.fn(),
};
const getReleaseByTag = jest.fn();
const Octokit = jest.fn(() => ({ repos: { getReleaseByTag } }));

jest.unstable_mockModule('@actions/core', () => ({ default: core }));
jest.unstable_mockModule('@actions/tool-cache', () => tc);
jest.unstable_mockModule('@octokit/rest', () => ({ Octokit }));
jest.unstable_mockModule('./cache-restore.js', () => ({ default: jest.fn() }));

const { downloadCLI, getDownloadRequest, isTrustedAssetUrl } = await import('./setup-tflint.js');

const ANONYMOUS_URL =
  'https://github.com/terraform-linters/tflint/releases/download/v0.61.0/tflint_linux_amd64.zip';
const ASSET_API_URL = 'https://api.github.com/repos/terraform-linters/tflint/releases/assets/123';

beforeEach(() => {
  jest.clearAllMocks();
  for (const key of Object.keys(inputs)) {
    delete inputs[key];
  }
});

describe('getDownloadRequest', () => {
  it('uses the anonymous download URL when no token is given', async () => {
    const request = await getDownloadRequest('v0.61.0', 'tflint_linux_amd64.zip');

    expect(request).toEqual({ url: ANONYMOUS_URL });
    expect(getReleaseByTag).not.toHaveBeenCalled();
  });

  it('downloads through the API with the token when one is given', async () => {
    inputs.github_token = 'ghs_test';
    getReleaseByTag.mockResolvedValue({
      data: {
        assets: [
          { name: 'tflint_darwin_amd64.zip', url: 'https://example.invalid/other' },
          { name: 'tflint_linux_amd64.zip', url: ASSET_API_URL },
        ],
      },
    });

    const request = await getDownloadRequest('v0.61.0', 'tflint_linux_amd64.zip');

    expect(getReleaseByTag).toHaveBeenCalledWith({
      owner: 'terraform-linters',
      repo: 'tflint',
      tag: 'v0.61.0',
    });
    expect(request).toEqual({
      url: ASSET_API_URL,
      auth: 'token ghs_test',
      headers: { accept: 'application/octet-stream' },
    });
  });

  it('falls back to the anonymous URL when the API lookup fails', async () => {
    inputs.github_token = 'ghs_test';
    getReleaseByTag.mockRejectedValue(new Error('Bad credentials'));

    const request = await getDownloadRequest('v0.61.0', 'tflint_linux_amd64.zip');

    expect(request).toEqual({ url: ANONYMOUS_URL });
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Bad credentials'));
  });

  it('falls back to the anonymous URL when the asset is missing', async () => {
    inputs.github_token = 'ghs_test';
    getReleaseByTag.mockResolvedValue({ data: { assets: [] } });

    const request = await getDownloadRequest('v0.61.0', 'tflint_linux_amd64.zip');

    expect(request).toEqual({ url: ANONYMOUS_URL });
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('not found'));
  });

  it('does not send the token when the asset URL is not the tflint asset API', async () => {
    inputs.github_token = 'ghs_test';
    getReleaseByTag.mockResolvedValue({
      data: {
        assets: [{ name: 'tflint_linux_amd64.zip', url: 'https://evil.example/assets/123' }],
      },
    });

    const request = await getDownloadRequest('v0.61.0', 'tflint_linux_amd64.zip');

    expect(request).toEqual({ url: ANONYMOUS_URL });
    expect(core.warning).toHaveBeenCalledWith(expect.stringContaining('Unexpected asset URL'));
  });
});

describe('isTrustedAssetUrl', () => {
  it('accepts the tflint release asset API URL', () => {
    expect(isTrustedAssetUrl(ASSET_API_URL)).toBe(true);
  });

  it.each([
    ['another host', 'https://evil.example/repos/terraform-linters/tflint/releases/assets/123'],
    [
      'a look-alike host',
      'https://api.github.com.evil.example/repos/terraform-linters/tflint/releases/assets/123',
    ],
    [
      'credentials in the URL',
      'https://user@api.github.com/repos/terraform-linters/tflint/releases/assets/123',
    ],
    ['plain HTTP', 'http://api.github.com/repos/terraform-linters/tflint/releases/assets/123'],
    [
      'a non-default port',
      'https://api.github.com:8443/repos/terraform-linters/tflint/releases/assets/123',
    ],
    ['another repository', 'https://api.github.com/repos/evil/tflint/releases/assets/123'],
    [
      'another API path',
      'https://api.github.com/repos/terraform-linters/tflint/releases/assets/123/../../../../user',
    ],
    [
      'a query string',
      'https://api.github.com/repos/terraform-linters/tflint/releases/assets/123?x=1',
    ],
    [
      'a non-numeric asset id',
      'https://api.github.com/repos/terraform-linters/tflint/releases/assets/abc',
    ],
    ['an invalid URL', 'not a url'],
    ['a missing URL', undefined],
  ])('rejects %s', (_label, url) => {
    expect(isTrustedAssetUrl(url)).toBe(false);
  });
});

describe('downloadCLI', () => {
  it('passes auth and headers to the download', async () => {
    tc.downloadTool.mockResolvedValue('/tmp/tflint.zip');
    tc.extractZip.mockResolvedValue('/tmp/tflint');

    await downloadCLI(
      {
        url: ASSET_API_URL,
        auth: 'token ghs_test',
        headers: { accept: 'application/octet-stream' },
      },
      [],
      'v0.61.0',
    );

    expect(tc.downloadTool).toHaveBeenCalledWith(ASSET_API_URL, undefined, 'token ghs_test', {
      accept: 'application/octet-stream',
    });
  });

  it('downloads anonymously without auth', async () => {
    tc.downloadTool.mockResolvedValue('/tmp/tflint.zip');
    tc.extractZip.mockResolvedValue('/tmp/tflint');

    await downloadCLI({ url: ANONYMOUS_URL }, [], 'v0.61.0');

    expect(tc.downloadTool).toHaveBeenCalledWith(ANONYMOUS_URL, undefined, undefined, undefined);
  });
});
