import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { pipeline } from 'stream/promises';

import * as core from '@actions/core';
import exec from '@actions/exec';
import io from '@actions/io';
import * as tc from '@actions/tool-cache';
import { Octokit } from '@octokit/rest';

import restoreCache from './cache-restore.js';

/**
 * Normalize version for tool-cache compatibility
 * @param {string} version - Version string (e.g., "v0.50.0" or "0.50.0")
 * @returns {string} - Normalized version without "v" prefix
 */
function normalizeVersion(version) {
  return version.replace(/^v/, '');
}

/**
 * Get the GitHub platform architecture name
 * @param {string} arch - https://nodejs.org/api/os.html#os_os_arch
 * @returns {string}
 */
function mapArch(arch) {
  const mappings = {
    x32: '386',
    x64: 'amd64',
  };
  return mappings[arch] || arch;
}

/**
 * Get the GitHub OS name
 * @param {string} osPlatform - https://nodejs.org/api/os.html#os_os_platform
 * @returns {string}
 */
function mapOS(osPlatform) {
  const mappings = {
    win32: 'windows',
  };
  return mappings[osPlatform] || osPlatform;
}

function getOctokit() {
  return new Octokit({
    auth: core.getInput('github_token'),
  });
}

async function getTFLintVersion(inputVersion) {
  if (!inputVersion || inputVersion === 'latest') {
    const octokit = getOctokit();
    const response = await octokit.repos.getLatestRelease({
      owner: 'terraform-linters',
      repo: 'tflint',
    });
    core.debug(`... version resolved to [${response.data.name}]`);
    return response.data.name;
  }

  return inputVersion;
}

async function fileSHA256(filePath) {
  const hash = crypto.createHash('sha256');
  const fileStream = fs.createReadStream(filePath); // eslint-disable-line security/detect-non-literal-fs-filename

  await pipeline(fileStream, hash);
  return hash.digest('hex');
}

/**
 * Check that a URL is the GitHub API endpoint of a tflint release asset.
 * @param {string} url - Asset URL returned by the GitHub API
 * @returns {boolean}
 */
function isTrustedAssetUrl(url) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  return (
    parsed.origin === 'https://api.github.com' &&
    !parsed.username &&
    !parsed.password &&
    !parsed.search &&
    !parsed.hash &&
    /^\/repos\/terraform-linters\/tflint\/releases\/assets\/\d+$/.test(parsed.pathname)
  );
}

/**
 * Resolve how to download the release asset.
 *
 * With a token, the asset is fetched through the REST API so the request is authenticated.
 * GitHub can throttle anonymous release downloads (e.g. 504/429 for unauthenticated traffic),
 * and the plain github.com download URL does not use the token at all.
 * Without a token, or when the API lookup fails, fall back to the anonymous download URL.
 * @param {string} version - Release tag (e.g. "v0.50.0")
 * @param {string} assetName - Asset file name (e.g. "tflint_linux_amd64.zip")
 * @returns {Promise<{url: string, auth?: string, headers?: object}>}
 */
async function getDownloadRequest(version, assetName) {
  const anonymous = {
    url: `https://github.com/terraform-linters/tflint/releases/download/${version}/${assetName}`,
  };

  const token = core.getInput('github_token');
  if (!token) {
    return anonymous;
  }

  try {
    const octokit = getOctokit();
    const { data: release } = await octokit.repos.getReleaseByTag({
      owner: 'terraform-linters',
      repo: 'tflint',
      tag: version,
    });
    const asset = release.assets.find((a) => a.name === assetName);
    if (!asset) {
      throw new Error(`Asset ${assetName} not found in release ${version}`);
    }

    // Never send the token anywhere other than the API endpoint for tflint's release assets.
    if (!isTrustedAssetUrl(asset.url)) {
      throw new Error(`Unexpected asset URL ${asset.url}`);
    }

    // The API redirects to a different host; @actions/http-client drops the Authorization header there.
    return {
      url: asset.url,
      auth: `token ${token}`,
      headers: { accept: 'application/octet-stream' },
    };
  } catch (error) {
    core.warning(
      `Failed to resolve the release asset via the GitHub API (${error.message}). Falling back to an anonymous download.`,
    );
    return anonymous;
  }
}

async function downloadCLI(request, checksums, version) {
  const { url, auth, headers } = request;
  core.info(`Attempting to download ${version}...`);
  core.info(`Acquiring ${version} from ${url}${auth ? ' (authenticated)' : ''}`);
  const pathToCLIZip = await tc.downloadTool(url, undefined, auth, headers);

  if (checksums.length > 0) {
    core.debug('Verifying checksum of downloaded file');

    const checksum = await fileSHA256(pathToCLIZip);

    if (!checksums.includes(checksum)) {
      throw new Error(
        `Mismatched checksum: expected one of ${checksums.join(', ')}, but got ${checksum}`,
      );
    }

    core.debug('SHA256 hash verified successfully');
  }

  core.info('Extracting...');
  const pathToCLI = await tc.extractZip(pathToCLIZip);
  core.debug(`tflint CLI path is ${pathToCLI}.`);

  if (!pathToCLIZip || !pathToCLI) {
    throw new Error(`Unable to download tflint from ${url}`);
  }

  return pathToCLI;
}

async function getInstalledVersion() {
  try {
    let stdout = '';
    await exec.exec('tflint', ['--version'], {
      listeners: {
        stdout: (data) => {
          stdout += data.toString();
        },
      },
    });

    const firstLine = stdout.split('\n')[0];
    const match = firstLine.match(/TFLint version (.+)/);
    if (match) {
      const installedVersion = match[1];
      core.setOutput('tflint-version', installedVersion);
    } else {
      core.warning('Unable to parse tflint version from output');
    }
  } catch (error) {
    core.warning(`Failed to get tflint version: ${error.message}`);
  }
}

async function installWrapper(pathToCLI) {
  // Move the original tflint binary to a new location
  await io.mv(path.join(pathToCLI, 'tflint'), path.join(pathToCLI, 'tflint-bin'));

  // Copy the wrapper script to the tflint binary location
  await io.cp(
    path.resolve(path.join(__dirname, '..', 'wrapper', 'dist', 'index.js')),
    path.join(pathToCLI, 'tflint'),
  );

  // Copy the wrapper script package.json to the tflint binary location
  await io.cp(
    path.resolve(path.join(__dirname, '..', 'wrapper', 'dist', 'package.json')),
    path.join(pathToCLI, 'package.json'),
  );

  core.exportVariable('TFLINT_CLI_PATH', pathToCLI);
}

async function run() {
  try {
    await restoreCache();

    const inputVersion = core.getInput('tflint_version');
    const checksums = core.getMultilineInput('checksums');
    const wrapper = core.getInput('tflint_wrapper') === 'true';
    const version = await getTFLintVersion(inputVersion);
    const platform = mapOS(os.platform());
    const arch = mapArch(os.arch());
    const normalizedVersion = normalizeVersion(version);

    // Check if tool is already cached
    let pathToCLI = tc.find('tflint', normalizedVersion, arch);
    if (pathToCLI) {
      core.info(`Found TFLint ${version} in cache @ ${pathToCLI}`);
    } else {
      core.debug(`Getting download URL for tflint version ${version}: ${platform} ${arch}`);
      const request = await getDownloadRequest(version, `tflint_${platform}_${arch}.zip`);

      pathToCLI = await downloadCLI(request, checksums, version);

      core.info('Adding to the tool cache...');
      pathToCLI = await tc.cacheDir(pathToCLI, 'tflint', normalizedVersion, arch);
      core.info(`Successfully cached TFLint to ${pathToCLI}`);
    }

    core.addPath(pathToCLI);

    const matchersPath = path.join(__dirname, '..', '.github', 'matchers.json');
    core.info(`##[add-matcher]${matchersPath}`);

    await getInstalledVersion();

    // Must happen after version detection and caching, which depend on the real binary
    if (wrapper) {
      await installWrapper(pathToCLI);
    }

    return version;
  } catch (ex) {
    core.error(ex);
    throw ex;
  }
}

export default run;

// Exported for testing
export { downloadCLI, getDownloadRequest, isTrustedAssetUrl };
