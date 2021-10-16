#!/usr/bin/python3
from bs4 import BeautifulSoup
import argparse
import urllib.request

parser = argparse.ArgumentParser(description='Extracts href links from a website.')
parser.add_argument('url', type=str, help='website url')
args = parser.parse_args()

html_page = urllib.request.urlopen(args.url)
soup = BeautifulSoup(html_page, "html.parser")
links = set()
for link in soup.findAll('a'):
    links.add(link.get('href'))

for link in links:
    print(link)
