"""Explicit local S05 command-line routes. Author: Antonio Clim."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import stat
import sys
import codeprobe_interpretation as interpretation
import codeprobe_reporting as reporting


def safe_path(path: Path) -> Path:
    absolute = path.absolute()
    if any(p.is_symlink() for p in (absolute, *absolute.parents)):
        raise reporting.ReportingError('symlink path components are not admitted')
    return absolute


def read_regular(path: Path, limit: int) -> bytes:
    target = safe_path(path)
    before = target.lstat()
    if not stat.S_ISREG(before.st_mode): raise reporting.ReportingError('regular file required')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_CLOEXEC', 0)
    fd = os.open(target, flags)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev,before.st_ino) != (opened.st_dev,opened.st_ino):
            raise reporting.ReportingError('source identity changed during admission')
        chunks = []; count = 0
        while True:
            chunk = os.read(fd, min(65536, limit - count + 1))
            if not chunk: break
            chunks.append(chunk); count += len(chunk)
            if count > limit: raise reporting.ReportingError('file exceeds declared byte budget')
        after = os.fstat(fd)
        if any(getattr(opened,k) != getattr(after,k) for k in ('st_dev','st_ino','st_size','st_mtime_ns')) or count != opened.st_size:
            raise reporting.ReportingError('source changed while being read')
        return b''.join(chunks)
    finally: os.close(fd)


def write_outputs(directory: Path, bundle: dict, rendered: bytes) -> None:
    target = safe_path(directory)
    if target == reporting.ROOT or reporting.ROOT in target.parents:
        raise reporting.ReportingError('report output must be outside source')
    # Reserve an absent directory atomically; never overwrite an existing output.
    target.mkdir(mode=0o700)
    written = []
    try:
        for name, data in [('report.json', interpretation.canonical(bundle) + b'\n'), ('report.html', rendered)]:
            dest = target / name
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            written.append(dest)
            with os.fdopen(fd, 'wb') as handle: handle.write(data)
    except Exception:
        for dest in written:
            try: dest.unlink()
            except OSError: pass
        try: target.rmdir()
        except OSError: pass
        raise


class PrivateArgumentParser(argparse.ArgumentParser):
    """Reject malformed syntax without echoing user-supplied argument values."""
    def error(self, message):
        self.exit(2, json.dumps({'status': 'refused', 'operation': 'argument_admission',
            'message': 'Invalid or incomplete command. Use --help and supply the required options; argument values are not echoed.'}) + '\n')


def main(argv=None) -> int:
    parser = PrivateArgumentParser(description='CodeProbe S05: explicit local review, not authorship inference.')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('profiles', help='List exact profile identifiers and digests')
    for command in ('generate','render','verify','check-feedback'):
        p = sub.add_parser(command)
        p.add_argument('--source', type=Path, required=True)
        p.add_argument('--language', required=True)
        p.add_argument('--profile', required=True)
        p.add_argument('--profile-sha', required=True)
        p.add_argument('--include-source', action='store_true')
        p.add_argument('--disclose-path', action='store_true')
        if command != 'generate': p.add_argument('--bundle',type=Path,required=True)
        if command in ('generate','render'): p.add_argument('--output-dir',type=Path,required=True)
        if command == 'check-feedback': p.add_argument('--feedback',type=Path,required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'profiles':
            print(json.dumps(interpretation.available_profiles(), sort_keys=True)); return 0
        data = read_regular(args.source, 1_000_000)
        context = dict(language=args.language, profile_id=args.profile, profile_sha256=args.profile_sha,
                       include_source=args.include_source, path=str(args.source.absolute()) if args.disclose_path else reporting.NEUTRAL_PATH)
        if args.command == 'generate': bundle = reporting.make_bundle(data,**context)
        else:
            bundle = interpretation.strict_json(read_regular(args.bundle,4_000_000))
            reporting.verify_bundle(bundle,data,**context)
        if args.command in ('generate','render'):
            rendered = reporting.render_html(bundle,data,**context)
            write_outputs(args.output_dir,bundle,rendered)
        if args.command == 'check-feedback':
            journal = interpretation.strict_json(read_regular(args.feedback,4_000_000))
            reporting.validate_feedback(journal,bundle,data,**context)
        print(json.dumps({'status':'completed','operation':args.command,'report_digest':bundle['digest'],
                          'qualification':'Scoped replay/structural admission only; not empirical validation or authentication.'},sort_keys=True))
        return 0
    except (OSError,ValueError,TypeError,KeyError,RecursionError,MemoryError) as exc:
        # Never print source bytes, user paths, raw exception strings or tracebacks.
        code = getattr(exc,'code',None)
        if code is not None and not isinstance(code,str): code = None
        print(json.dumps({'status':'refused','operation':args.command,'code':code,
            'message':'No completed report. Check the source encoding, size, regular-file paths, explicit profile/digest and absent output directory. Correct the input and retry. Existing reports are not overwritten.'}),file=sys.stderr)
        return 2


if __name__ == '__main__': raise SystemExit(main())
