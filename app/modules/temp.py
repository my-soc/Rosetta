import requests
from bs4 import BeautifulSoup
import random
from faker import Faker


# Send a GET request to the MITRE ATT&CK Enterprise Techniques page
url = 'https://attack.mitre.org/techniques/enterprise/'
response = requests.get(url)

# Parse the HTML content of the response using BeautifulSoup
soup = BeautifulSoup(response.content, 'html.parser')

# Find the table element on the page
table = soup.find('table')

# Extract the third column of the table
terms = [td.text.strip() for td in table.find_all('td') ]
# Choose a random term from the list

fake = Faker()

product_description = fake.paragraph(nb_sentences=1, ext_word_list=terms)

print (product_description)