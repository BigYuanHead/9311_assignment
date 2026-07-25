import sys

from src.dns_resolver import resolver_C



def main():
    root_hints_file = sys.argv[1]
    timeout = sys.argv[2]
    listen_port = sys.argv[3]

    resolver = resolver_C(root_hints_file, timeout, listen_port)
    resolver.start()


if __name__ == '__main__':
    main()