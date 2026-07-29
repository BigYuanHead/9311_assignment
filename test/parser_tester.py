

from pathlib import Path
import sys
import io
from contextlib import redirect_stdout


# Parser tester for the assignment resource .bin files.
# It directly uses your request_parser.py and dnsDisplay.py.
#
# It does NOT build a DNS response.
# It only checks whether your parser can correctly parse:
#     xxx-query.bin
#     xxx-response.bin
#
# Then it prints the decoded display for both files.

BASE_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = BASE_DIR / 'src'
RESOURCE_DIR = BASE_DIR / 'dns-assignment-resources'

# Allow both styles used in your files:
#     import src.request_parser
#     import dataStructures.dns_dataTypes
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(SRC_DIR))

import src.request_parser as RP
import src.helpers.dnsDisplay as DD


def read_bytes(path: Path) -> bytes:
    with open(path, 'rb') as file:
        return file.read()


def parse_file(path: Path):
    data = read_bytes(path)
    parser = RP.dnsParser_C(data=data)
    request = parser.parse()
    return request


def display_to_text(request) -> str:
    output = io.StringIO()
    with redirect_stdout(output):
        display = DD.dnsDisplay_C(request)
        display.display()
    return output.getvalue()


def print_one_file(path: Path):
    request = parse_file(path)

    print('FILE: {}'.format(path.name))

    if getattr(request, 'is_malformed', False):
        print('MALFORMED: {}'.format(request.malformed_reason))
        print()
        return False

    print(display_to_text(request), end='')
    return True


def expected_response_path(query_path: Path) -> Path:
    return query_path.with_name(
        query_path.name.replace('-query.bin', '-response.bin')
    )


def find_query_files():
    if not RESOURCE_DIR.exists():
        raise RuntimeError('Cannot find resource folder: {}'.format(RESOURCE_DIR))

    return sorted(RESOURCE_DIR.glob('*-query.bin'))


def run_one_pair(query_path: Path):
    response_path = expected_response_path(query_path)

    print('=' * 70)
    print('TEST PAIR: {}'.format(query_path.name.replace('-query.bin', '')))
    print('=' * 70)

    if not response_path.exists():
        print('Missing response file: {}'.format(response_path.name))
        return False

    print('--- QUERY BIN ---')
    query_ok = print_one_file(query_path)

    print('--- RESPONSE BIN ---')
    response_ok = print_one_file(response_path)

    return query_ok and response_ok


def main():
    query_files = find_query_files()

    if len(query_files) == 0:
        print('No *-query.bin files found in {}'.format(RESOURCE_DIR))
        return

    passed = 0
    failed = 0

    for query_path in query_files:
        try:
            ok = run_one_pair(query_path)
        except Exception as e:
            raise e
            ok = False
            print('ERROR while testing {}'.format(query_path.name))
            print(e)

        if ok:
            passed = passed + 1
        else:
            failed = failed + 1

    print('=' * 70)
    print('Summary: {} pairs parsed, {} pairs failed/malformed'.format(
        passed,
        failed,
    ))


if __name__ == '__main__':
    main()