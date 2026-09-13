"""Build the pinned PSMF or raw MPEG2-PS reader as one Linux x64 executable."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tarfile
import tempfile

REVISION = '1bc01f9ffbfb97adc9bb384c44e081398b9a93e4'
SDK_VERSION = '8.0.425'
RUNTIME_VERSION = '8.0.31'
BUILD_TIMEOUT = 900
ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / 'tools/patches/pmftools-traversal.patch'
MPEGPS_PATCH = ROOT / 'tools/patches/pmftools-mpegps.patch'


def run(command, *, cwd, env=None, timeout=60, capture=False):
    # Kill the whole build on timeout, including any non-server MSBuild children.
    with subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE if capture else None,
                          start_new_session=True) as process:
        try:
            stdout, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
        return stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--dotnet', default='dotnet')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--format', choices=('psmf', 'mpegps'), default='psmf')
    args = parser.parse_args()
    assembly = 'pspdb-' + args.format
    source = args.source.expanduser().resolve()
    output = args.output.expanduser().absolute()
    dotnet_name = shutil.which(os.path.expanduser(args.dotnet))
    if dotnet_name is None:
        parser.error(f'.NET SDK executable not found: {args.dotnet}')
    dotnet = Path(dotnet_name).resolve()
    resolved_output = output.resolve()
    if (resolved_output.is_relative_to(source)
            or resolved_output.is_relative_to(dotnet.parent)
            or resolved_output in (Path(__file__).resolve(), PATCH.resolve(),
                                   MPEGPS_PATCH.resolve())):
        parser.error('Output would overwrite a build input')
    try:
        with tempfile.TemporaryDirectory(prefix=assembly + '-build-') as tmp:
            work = Path(tmp)
            # Archive the named commit, never the checkout's mutable working tree.
            revision = run(['git', '--no-replace-objects', '-C', str(source),
                            'rev-parse', '--verify', REVISION + '^{commit}'],
                           cwd=work, capture=True)
            if revision.decode().strip() != REVISION:
                raise ValueError('Upstream commit does not match the pinned revision')
            archive = run(['git', '--no-replace-objects', '-C', str(source),
                           'archive', REVISION + '^{commit}'], cwd=work, capture=True)
            checkout = work / 'source'
            checkout.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                tar.extractall(checkout, filter='data')
            # Snapshot the patch so its reported fingerprint identifies applied bytes.
            patch_bytes = PATCH.read_bytes()
            patch_hash = hashlib.sha256(patch_bytes).hexdigest()
            patch = work / 'traversal.patch'
            patch.write_bytes(patch_bytes)
            run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(patch)], cwd=checkout)
            if args.format == 'mpegps':
                raw_patch_bytes = MPEGPS_PATCH.read_bytes()
                raw_patch_hash = hashlib.sha256(raw_patch_bytes).hexdigest()
                raw_patch = work / 'mpegps.patch'
                raw_patch.write_bytes(raw_patch_bytes)
                run(['patch', '--batch', '--fuzz=0', '-p1', '-i', str(raw_patch)], cwd=checkout)
            (checkout / 'global.json').write_text(json.dumps({
                'sdk': {'version': SDK_VERSION, 'rollForward': 'disable',
                        'allowPrerelease': False},
            }) + '\n')
            home = work / 'home'
            home.mkdir()
            env = os.environ.copy()
            env.update({
                'HOME': str(home),
                'DOTNET_CLI_HOME': str(home),
                'DOTNET_ROOT': str(dotnet.parent),
                'DOTNET_MULTILEVEL_LOOKUP': '0',
                'DOTNET_CLI_TELEMETRY_OPTOUT': '1',
                'DOTNET_SKIP_FIRST_TIME_EXPERIENCE': '1',
                'DOTNET_NOLOGO': '1',
                'DOTNET_CLI_USE_MSBUILD_SERVER': '0',
                'MSBUILDDISABLENODEREUSE': '1',
                'NUGET_PACKAGES': str(work / 'nuget'),
                'NUGET_HTTP_CACHE_PATH': str(work / 'nuget-http'),
            })
            publish = work / 'publish'
            run([
                str(dotnet), 'publish', 'psmfdump/psmfdump.csproj',
                '--configuration', 'Release', '--runtime', 'linux-x64',
                '--self-contained', 'true', '--output', str(publish),
                '--disable-build-servers',
                '-p:RuntimeFrameworkVersion=' + RUNTIME_VERSION,
                '-p:TargetLatestRuntimePatch=false',
                '-p:AssemblyName=' + assembly,
                '-p:PublishSingleFile=true',
                '-p:IncludeNativeLibrariesForSelfExtract=true',
                '-p:IncludeAllContentForSelfExtract=true',
                '-p:PublishTrimmed=false',
                '-p:PublishReadyToRun=false',
                '-p:DebugType=None', '-p:DebugSymbols=false',
                '-p:Deterministic=true', '-p:ContinuousIntegrationBuild=true',
                '-p:PathMap=' + str(checkout) + '=/_/pmftools',
                '-p:UseSharedCompilation=false', '-nodeReuse:false',
                '-p:RestoreSources=https://api.nuget.org/v3/index.json',
            ], cwd=checkout, env=env, timeout=BUILD_TIMEOUT)
            executable = publish / assembly
            if (set(publish.iterdir()) != {executable}
                    or not executable.is_file() or executable.is_symlink()):
                raise ValueError('Publication must contain exactly one executable, without sidecars')
            output.parent.mkdir(parents=True, exist_ok=True)
            # A sibling staging directory keeps replacement atomic on this filesystem.
            with tempfile.TemporaryDirectory(prefix='.' + assembly + '-', dir=output.parent) as stage:
                staged = Path(stage) / assembly
                shutil.copyfile(executable, staged)
                staged.chmod(0o755)
                with staged.open('rb') as stream:
                    digest = hashlib.file_digest(stream, 'sha256').hexdigest()
                os.replace(staged, output)
    except subprocess.TimeoutExpired as error:
        parser.exit(1, f'error: build command timed out after {error.timeout} seconds\n')
    except (OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'error: {error}\n')
    print(output)
    print(f'upstream {REVISION}')
    print(f'patch SHA256 {patch_hash}')
    if args.format == 'mpegps':
        print(f'mpegps patch SHA256 {raw_patch_hash}')
    print(f'SHA256 {digest}')


if __name__ == '__main__':
    main()
