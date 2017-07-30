#!/usr/bin/python

__author__ = "Sumit Shrivastava"
__version__ = "v1.0.0"

import re, sys

# Generic regular expressions
preferred_cipher_re = re.compile(r"^Preferred")
accepted_cipher_re = re.compile(r"^Accepted")
color_code_re = re.compile(r"\033\[[0-9;]+m")
not_re = re.compile(r"not")
application_re = re.compile(r"^Testing")

# Vulnerabilities regular expressions
logjam_re = re.compile(r"\-?(\bDHE\b|\bEDH\b)\-?")
weak_ciphers_re = re.compile(r"\-?(\bCBC\b|\bCBC3\b|\bRC2\b|\bRC4\b|\bNULL\b|\bAnon\b)\-?")
obsolete_version_re = re.compile(r"TLSv1.0|SSLv3|SSLv2")
ssl_poodle_re = re.compile(r"SSLv3|TLSv1.0")
tls_beast_re = re.compile(r"TLSv1.0")
ssl_drown_re = re.compile(r"SSLv2")
heartbleed_re = re.compile(r"heartbleed")
crime_re = re.compile(r"^Compression\s(enabled|disabled)")

vulnerabilities = {}
logjam = []
weak_ciphers = []
obsolete_version = []
ssl_poodle = False
ssl_drown = False
crime = False
heartbleed = False
beast = False


def unique_list(mylist = []):
    return list(set(mylist))


def remove_color(file_data = []):
    clean_file_data = []
    for line in file_data:
        line = color_code_re.sub("", line)
        clean_file_data.append(line)
    return clean_file_data


def check_cipher_vulnerabilities(line = ""):
    # this will check vulnerabilities in cipher suites
    if crime_re.match(line):
        if crime_re.match(line).group(1) == "enabled":
            crime = True
        if ssl_drown_re.search(line):
            ssl_drown = True
        if ssl_poodle_re.search(line):
            ssl_poodle = True
        if heartbleed_re.search(line):
            if not(not_re.search(line)):
                heartbleed = True
        if tls_beast_re.search(line):
            beast = True


def check_ssl_vulnerabilities(line = ""):
    # this will check vulnerabilities in ssl configuration
    line_split = line.split(" ")
    cipher_text = False
    if preferred_cipher_re.match(line):
        ssl_ver = line_split[1]
        cipher = line_split[6]
        cipher_text = True
    if accepted_cipher_re.match(line):
        ssl_ver = line_split[2]
        cipher = line_split[7]
        cipher_text = True
    if cipher_text:
        if obsolete_version_re.match(ssl_ver):
            obsolete_version.append(ssl_ver)
        if weak_ciphers_re.match(cipher):
            weak_ciphers.append(cipher)
        if logjam_re.match(cipher):
            logjam.append(cipher)


def report_vulnerabilities():
    vulnerabilities["heartbleed"] = heartbleed
    vulnerabilities["crime"] = crime
    vulnerabilities["drown"] = ssl_drown
    vulnerabilities["poodle"] = ssl_poodle
    vulnerabilities["beast"] = beast
    vulnerabilities["logjam"] = unique_list(logjam)
    vulnerabilities["weak_ciphers"] = unique_list(weak_ciphers)
    vulnerabilities["obsolete_versions"] = unique_list(obsolete_version)


def print_vulnerabilities():
    report_vulnerabilities()
    if vulnerabilities["heartbleed"]:
        print "[!] Heartbleed: Vulnerable"
    if vulnerabilities["crime"]:
        print "[!] Crime: Vulnerable"
    if vulnerabilities["poodle"]:
        print "[!] Poodle: Vulnerable"
    if vulnerabilities["beast"]:
        print "[!] Beast: Vulnerable"
    if vulnerabilities["drown"]:
        print "[!] Drown: Vulnerable"
    if len(vulnerabilities["logjam"]) > 0:
        print "\n[!] Following %d cipher(s) vulnerable to logjam attack:"%(len(vulnerabilities["logjam"]))
        for cipher in vulnerabilities["logjam"]:
            print cipher
    if len(vulnerabilities["weak_ciphers"]) > 0:
        print "\n[!] Following %d cipher(s) is / are considered cryptographically weak:"%(len(vulnerabilities["weak_ciphers"]))
        for cipher in vulnerabilities["weak_ciphers"]:
            print cipher
    if len(vulnerabilities["obsolete_versions"]) > 0:
        print "\n[!] Following %d SSL / TLS version(s) is / are obsolete:"%(len(vulnerabilities["obsolete_versions"]))
        for version in vulnerabilities["obsolete_versions"]:
            print version


def main():
    input_file = open(sys.argv[1], "r")
    input_data = input_file.readlines()
    input_file.close()
    input_data = remove_color(input_data)
    for line in input_data:
        if application_re.match(line):
            line_split = line.split(" ")
            application = line_split[3]
            port = line_split[6]
        check_ssl_vulnerabilities(line)
        check_cipher_vulnerabilities(line)
    print "[+] SSL Report for %s:%s"%(application, port)
    print_vulnerabilities()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "[-] Filename not provided"
        print "[!] Usage:", sys.argv[0], "<SSLScan_OUTPUT_FILE>"
        sys.exit(0)

    main()
