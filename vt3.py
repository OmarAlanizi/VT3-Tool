from datetime import datetime
import pathlib
import pandas as pd
import sys
import json
import re
from tabulate import tabulate
from vtapi3 import VirusTotalAPI, VirusTotalAPIFiles, VirusTotalAPIDomains, VirusTotalAPIIPAddresses, VirusTotalAPIError
from colorama import init, Back, Fore, Style
init()


class vt_tool():
    def __init__(self):
        self.api_key = None
        self.vt_api = None
        self.vt_api_files = None
        self.vt_api_ip_addresses = None
        self.vt_api_domains = None

        self.check_api_key()

    def banner(self, clear_screen=True):
        if clear_screen:
            print(chr(27) + "[2J")
        print(Fore.LIGHTBLUE_EX, '''[~] VT API v3 Tool [~]\n
    [1] (Re-)Enter API Key
    [2] Search for indicator
    [3] Print API Key
    [4] Upload file (NOT IMPLEMENTED)
    [5] Quit
        ''')

    def main(self, print_again=True, clear_screen=True):
        # make while loop
        if print_again:
            self.banner(clear_screen)
        choice = str(input('    [?] ')).strip()

        if choice == '1':
            self.api_key = None
            self.check_api_key(new_key=True)
            self.main(print_again=True, clear_screen=False)

        elif choice == '2':
            indicator = str(
                input('\n\t[*] Please enter the indicator\n\t[?] ')).strip()
            indicator_type = self.get_indicator_type(indicator)
            if (indicator_type == 'unknown'):
                print(chr(27) + "[2J")
                print(f'[*] Unknown type for indicator [{indicator}]')
                self.main(print_again=True, clear_screen=False)
            else:
                print(
                    f'[+] Searching for [{indicator}], with type [{indicator_type}]...', Fore.RESET)
                self.get_report(indicator, indicator_type)
                if (str(input('\t[?] Would you like to search again? [y/N]')).lower() == 'y'):
                    self.main(print_again=True, clear_screen=False)
                else:
                    sys.exit()

        elif choice == '3':
            self.check_api_key()
            print(chr(27) + "[2J")
            print('[*] API Key:', self.api_key, '\n')
            self.main(print_again=True, clear_screen=False)

        elif choice == '4':
            print(chr(27) + "[2J")
            print("[-] This feature hasn't beent implemented yet!\n")
            self.main(print_again=True, clear_screen=False)

        elif choice == '5':
            sys.exit()

        else:
            print(chr(27) + "[2J")
            print('[-] Unknown selection, please try again.')
            self.main(print_again=True, clear_screen=False)

    def check_api_key(self, new_key=False):
        api_key_file = pathlib.Path(str(pathlib.Path.cwd())+'\.apikey')
        if not new_key and not self.api_key and api_key_file.is_file():
            api_key = api_key_file.read_text()
            if api_key is not None and api_key != '':
                self.api_key = str(api_key)
        elif not self.api_key:
            choice = input(
                '[?] No API key found, would you like to save it in a new file (/.apikey) ? [y/N]')
            if choice.lower() == 'y':
                key = input('\t[*] Please enter your API key: ')
                self.api_key = str(key)
                api_key_file.write_text(key)

            elif choice.lower() == 'n':
                key = input(
                    '\t[*] Storing key in memory instead, enter your API key:')
                self.api_key = str(key)
            self.init_vt()

    def init_vt(self):
        if self.api_key is not None:
            if self.vt_api is None:
                self.vt_api = VirusTotalAPI(self.api_key)
            if self.vt_api_files is None:
                self.vt_api_files = VirusTotalAPIFiles(self.api_key)
            if self.vt_api_ip_addresses is None:
                self.vt_api_ip_addresses = VirusTotalAPIIPAddresses(
                    self.api_key)
            if self.vt_api_domains is None:
                self.vt_api_domains = VirusTotalAPIDomains(self.api_key)
            return (self.vt_api is not None
                    and self.vt_api_files is not None
                    and self.vt_api_ip_addresses is not None
                    and self.vt_api_domains is not None)
        elif self.api_key is None:
            self.check_api_key()
            self.init_vt()

    def get_report(self, indicator, indicator_type):
        self.init_vt()
        if indicator_type in ['MD5', 'SHA-1', 'SHA-256']:
            result = self.get_file_report(indicator)
            if result:
                comments = json.loads(self.vt_api_files.get_comments(indicator, 5))
                self.table_print_file(result, comments)
            elif result is None:
                print(chr(27) + "[2J")
                print(Fore.RED, '[*] Forbidden: Please check your API key.')
                self.main(print_again=True, clear_screen=False)
            else:
                print(chr(27) + "[2J")
                print(Fore.CYAN, '[*] No results found.')
                self.main(print_again=True, clear_screen=False)

        elif indicator_type == 'IP':
            result = self.get_ip_report(indicator)
            if result:
                comments = json.loads(self.vt_api_ip_addresses.get_comments(indicator, 5))
                print(comments)
                self.table_print_ip(result, comments)
            elif result is None:
                print(chr(27) + "[2J")
                print(Fore.RED, '[*] Forbidden: Please check your API key.')
                self.main(print_again=True, clear_screen=False)
            else:
                print(chr(27) + "[2J")
                print(Fore.CYAN, '[*] No results found.')
                self.main(print_again=True, clear_screen=False)

        elif indicator_type == 'Domain':
            result = self.get_domain_report(indicator)
            if result:
                comments = json.loads(self.vt_api_ip_addresses.get_comments(indicator, 5))
                self.table_print_domain(result, comments)
            elif result is None:
                print(chr(27) + "[2J")
                print(Fore.RED, '[*] Forbidden: Please check your API key.')
                self.main(print_again=True, clear_screen=False)
            else:
                print(chr(27) + "[2J")
                print(Fore.CYAN, '[*] No results found.')
                self.main(print_again=True, clear_screen=False)

    def get_file_report(self, indicator):
        self.init_vt()
        try:
            result = self.vt_api_files.get_report(indicator)
        except VirusTotalAPIError as err:
            print(err, err.err_code)

        if self.vt_api_files.get_last_http_error() == self.vt_api_files.HTTP_OK:
            result = json.loads(result)
            return result
        elif self.vt_api_files.get_last_http_error() == self.vt_api_files.HTTP_AUTHENTICATION_REQUIRED_ERROR:
            return None
        else:
            return {}

    def get_domain_report(self, indicator):
        self.init_vt()
        try:
            result = self.vt_api_domains.get_report(indicator)
        except VirusTotalAPIError as err:
            print(err, err.err_code)

        if self.vt_api_domains.get_last_http_error() == self.vt_api_domains.HTTP_OK:
            result = json.loads(result)
            return result
        elif self.vt_api_domains.get_last_http_error() == self.vt_api_domains.HTTP_AUTHENTICATION_REQUIRED_ERROR:
            print("ERROR")
            print(self.vt_api_domains.get_last_http_error())
            print(result)
            return None
        else:
            return {}

    def get_ip_report(self, indicator):
        self.init_vt()
        try:
            result = self.vt_api_ip_addresses.get_report(indicator)
        except VirusTotalAPIError as err:
            print(err, err.err_code)

        if self.vt_api_ip_addresses.get_last_http_error() == self.vt_api_ip_addresses.HTTP_OK:
            result = json.loads(result)
            return result
        elif self.vt_api_ip_addresses.get_last_http_error() == self.vt_api_ip_addresses.HTTP_AUTHENTICATION_REQUIRED_ERROR:
            return None
        else:
            print(
                'HTTP Error [' + str(self.vt_api_ip_addresses.get_last_http_error()) + ']')

    def table_print_ip(self, results, comments):
        try:
            if not results:
                return
            mydict = results['data']['attributes']['last_analysis_results']
            mydict = sorted(mydict.values(), reverse=True,
                            key=lambda value: value['category'])
            detected = 0
            for scan in mydict:
                if (scan['category'] and scan['category'].lower().strip() == 'malicious'):
                    scan['category'] = Fore.RED + scan['category'] + Fore.RESET
                    scan['result'] = Fore.RED + scan['result'] + Fore.RESET
                    detected += 1
                elif (scan['category'] and scan['category'].lower().strip() == 'suspicious'):
                    scan['category'] = Fore.YELLOW + \
                        scan['category'] + Fore.RESET
                    scan['result'] = Fore.YELLOW + scan['result'] + Fore.RESET
            df = pd.DataFrame(mydict)
            df.columns = ["Category", "Result",
                          "Method",  "Engine Name"]
            df.insert(0, '#', range(1, 1 + len(df)))
            cols = list(df.columns)
            a, b = cols.index('Engine Name'), cols.index('Category')
            cols[b], cols[a] = cols[a], cols[b]
            df = df[cols]
            print(tabulate(df, headers="keys",
                  tablefmt="fancy_grid", showindex=False))
            print(f'\n\t[+] Detected: {detected}/{len(df)}')
            # print(results.keys(), results['attributes'].keys())
            print(
                f"\t[+] Country: {results['data']['attributes']['country']}\t[+] AS {results['data']['attributes']['asn']} ({results['data']['attributes']['as_owner']})")
            print(
                f"\t[+] Reputation: {results['data']['attributes']['reputation']}\n")
            print("\t[+] Comments")

            for comment in comments['data']:
                print(f"\t[{datetime.fromtimestamp(comment['attributes']['date'])}]: {comment['attributes']['text']}")

            print('\n')
        except KeyError as e:
            print(e)

    def table_print_domain(self, results, comments):
        try:
            if not results:
                return
            mydict = results['data']['attributes']['last_analysis_results']
            mydict = sorted(mydict.values(), reverse=True,
                            key=lambda value: value['category'])
            detected = 0
            for scan in mydict:
                if (scan['category'] and scan['category'].lower().strip() == 'malicious'):
                    scan['category'] = Fore.RED + scan['category'] + Fore.RESET
                    scan['result'] = Fore.RED + scan['result'] + Fore.RESET
                    detected += 1
                elif (scan['category'] and scan['category'].lower().strip() == 'suspicious'):
                    scan['category'] = Fore.YELLOW + \
                        scan['category'] + Fore.RESET
                    scan['result'] = Fore.YELLOW + scan['result'] + Fore.RESET
            df = pd.DataFrame(mydict)
            df.columns = ["Category", "Result",
                          "Method",  "Engine Name"]
            df.insert(0, '#', range(1, 1 + len(df)))
            cols = list(df.columns)
            a, b = cols.index('Engine Name'), cols.index('Category')
            cols[b], cols[a] = cols[a], cols[b]
            df = df[cols]
            print(tabulate(df, headers="keys",
                  tablefmt="fancy_grid", showindex=False))
            print(f'\n\t[+] Detected: {detected}/{len(df)}')
            print(
                f"\t[+] Reputation: {results['data']['attributes']['reputation']}")
            print(f"\t[*] Categories:")
            for k, v in results['data']['attributes']['categories'].items():
                print('\t\t', k, ':', v)
            print("\t[+] Comments")

            for comment in comments['data']:
                print(f"\t[{datetime.fromtimestamp(comment['attributes']['date'])}]: {comment['attributes']['text']}")

            print('\n')
        except KeyError as e:
            print(e)

    def table_print_file(self, results, comments):
        try:
            if not results:
                return
            mydict = results['data']['attributes']['last_analysis_results']
            mydict = sorted(mydict.values(),
                            key=lambda value: value['category'])
            detected = 0
            for scan in mydict:
                if (scan['category'] and scan['category'].lower().strip() == 'malicious'):
                    scan['category'] = Fore.RED + scan['category'] + Fore.RESET
                    scan['result'] = Fore.RED + scan['result'] + Fore.RESET
                    detected += 1
                elif (scan['category'] and scan['category'].lower().strip() == 'suspicious'):
                    scan['category'] = Fore.YELLOW + \
                        scan['category'] + Fore.RESET
                    scan['result'] = Fore.YELLOW + scan['result'] + Fore.RESET
            df = pd.DataFrame(mydict)
            df = df.drop('engine_update', axis=1)
            df.columns = ["Category", "Engine Name",
                          "Engine Version", "Result",  "Method"]
            df.insert(0, '#', range(1, 1 + len(df)))
            cols = list(df.columns)
            a, b = cols.index('Engine Name'), cols.index('Category')
            cols[b], cols[a] = cols[a], cols[b]
            df = df[cols]
            print(tabulate(df, headers="keys",
                  tablefmt="fancy_grid", showindex=False))
            print(f'\t\n[+] Detected: {detected}/{len(df)}')
            print(
                f"\t[+] First Submission: {datetime.fromtimestamp(results['data']['attributes']['first_submission_date'])}\tLast Submission: {datetime.fromtimestamp(results['data']['attributes']['last_submission_date'])}")
            print(f"\t[+] Last Analysis: {datetime.fromtimestamp(results['data']['attributes']['first_submission_date'])}\t\tReputation: {results['data']['attributes']['reputation']}\n\tSuggested Name: {results['data']['attributes']['popular_threat_classification']['suggested_threat_label']}")

            print("\t[+] Comments")

            for comment in comments['data']:
                print(f"\t[{datetime.fromtimestamp(comment['attributes']['date'])}]: {comment['attributes']['text']}")
            print('\n')
        except KeyError as e:
            print(e)

    def get_indicator_type(self, indicator):
        domain_regex = re.compile(
            r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
            r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
            r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
        )
        md5_regex = re.compile(
            r"^([a-fA-F\d]{32}$)"
        )
        sha1_regex = re.compile(
            r"^([a-fA-F\d]{40}$)"
        )
        sha256_regex = re.compile(
            r"^[A-Fa-f0-9]{64}$"
        )
        ipv4_regex = re.compile(
            r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
        )
        indicator_type = 'unknown'
        if md5_regex.match(indicator):
            indicator_type = "MD5"
        elif sha1_regex.match(indicator):
            indicator_type = "SHA-1"
        elif sha256_regex.match(indicator):
            indicator_type = "SHA-256"
        elif ipv4_regex.match(indicator):
            indicator_type = "IP"
        elif domain_regex.match(indicator):
            indicator_type = "Domain"
        return indicator_type


if __name__ == '__main__':
    # Colorama init
    init()

    vtapi3 = vt_tool()
    vtapi3.main()
