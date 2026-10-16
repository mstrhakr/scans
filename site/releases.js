'use strict';

async function showReleases() {
  const status = document.getElementById('stable-status');
  const list = document.getElementById('release-list');
  try {
    const response = await fetch('releases.json', { cache: 'no-cache' });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const manifest = await response.json();
    const versionPattern = /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
    if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.releases) ||
        !manifest.releases.some(release => release.version === manifest.stable)) {
      throw new Error('Invalid release manifest');
    }
    const cards = manifest.releases.map(release => {
      if (!versionPattern.test(release.version) || !/^[a-f0-9]{64}$/i.test(release.sha256) ||
          release.releaseUrl !== `https://github.com/printmaster-org/scans/releases/tag/${release.version}` ||
          release.url !== `https://github.com/printmaster-org/scans/releases/download/${release.version}/scans.ps1`) {
        throw new Error('Invalid release record');
      }
      const card = document.createElement('article');
      const title = document.createElement('h3');
      title.textContent = release.version + (release.version === manifest.stable ? ' — stable' : '');
      const notes = document.createElement('a');
      notes.href = release.releaseUrl;
      notes.textContent = 'Changes and downloads';
      const command = document.createElement('pre');
      const code = document.createElement('code');
      code.textContent = `& ([scriptblock]::Create((irm https://scans.printmaster.work/scans.ps1))) -Version '${release.version}'`;
      command.append(code);
      const hash = document.createElement('p');
      hash.className = 'checksum';
      hash.textContent = `SHA-256: ${release.sha256}`;
      card.append(title, notes, command, hash);
      return card;
    });
    list.replaceChildren(...cards);
    status.textContent = `Stable release: ${manifest.stable}`;
  } catch (error) {
    status.textContent = 'Release information is unavailable. Do not run setup until the release service is working.';
    list.textContent = `Could not load the release list: ${error.message}. See GitHub Releases for downloads and notes.`;
  }
}

showReleases();
