"""
CLI for MRSHw, to eliminate the need for a separate command line tool install.
"""

import argparse
import sys
from pathlib import Path
from . import hash, __version__
from .utils import scan_directory


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="MRSH - Malware Resistant Similarity Hashing")
    parser.add_argument('--version', action='version', version=f'MRSH {__version__}')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Hash command
    hash_parser = subparsers.add_parser('hash', help='Generate hash for a file')
    hash_parser.add_argument('file', help='File to hash')

    # Compare command
    compare_parser = subparsers.add_parser('compare', help='Compare two files or hashes')
    compare_parser.add_argument('input1', help='First file or hash')
    compare_parser.add_argument('input2', help='Second file or hash')
    compare_parser.add_argument('--threshold', '-t', type=int, default=0,
                               help='Similarity threshold')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan directory for similar files')
    scan_parser.add_argument('directory', help='Directory to scan')
    scan_parser.add_argument('--recursive', '-r', action='store_true',
                            help='Scan recursively')
    scan_parser.add_argument('--threshold', '-t', type=int, default=50,
                            help='Similarity threshold')
    scan_parser.add_argument('--extensions', '-e', nargs='*',
                            help='File extensions to include')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    try:
        if args.command == 'hash':
            result = hash(args.file)
            print(result)

        elif args.command == 'compare':
            if Path(args.input1).exists() and Path(args.input2).exists():
                # Compare files
                from . import Fingerprint
                fp1 = Fingerprint(args.input1)
                fp2 = Fingerprint(args.input2)
                score = fp1.compare(fp2)
                print(f"Similarity score: {score}")
            else:
                # Compare hashes
                from . import diff
                score = diff(args.input1, args.input2)
                print(f"Difference score: {score}")

        elif args.command == 'scan':
            fpl = scan_directory(args.directory, args.extensions, args.recursive)
            results = fpl.compare_all(args.threshold)

            if results:
                print("Similar files found:")
                for comp in results:
                    print(f"  {comp.hash1} <-> {comp.hash2} (score: {comp.score})")
            else:
                print("No similar files found.")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
