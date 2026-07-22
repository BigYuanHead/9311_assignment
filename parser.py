import os
import sys

import src.helpers.myLogger as myL

import src.helpers.dnsDisplay as DDSP
from src.dnsRequest_parser import dnsParser_C


def main(filename=None):

    if filename is None:
        if len(sys.argv) != 2:
            print('Usage: python3 parser.py message_file')
            return
        filename = sys.argv[1]  

    parser = dnsParser_C(filename)
    parser.parse()

    display = DDSP.dnsDisplay_C(parser)
    display.display()


folder = 'dns-assignment-resources'
bin_files = []

# collect all .bin files
for filename in os.listdir(folder):
    if filename.endswith('.bin'):
        full_path = os.path.join(folder, filename)
        bin_files.append(full_path)

bin_files.sort()

if len(bin_files) == 0:
    print('No .bin files found in {}'.format(folder))
else:
    print('Available DNS message files:')
    print(myL.SEP_LINE)

    for idx in range(len(bin_files)):
        print('{}: {}'.format(idx + 1, bin_files[idx]))

    print(myL.SEP_LINE)
    user_input = input('Choose file number: ')

    try:
        choice = int(user_input)

        if choice < 1 or choice > len(bin_files):
            print('Invalid choice')
        else:
            selected_file = bin_files[choice - 1]
            print('Selected: {}'.format(selected_file))
            print(myL.SEP_LINE)
            main(selected_file)

    except ValueError:
        print('Please enter a number')
