Tool that provides all IP address blocks assigned to an Autonomous System (AS).

Usage:

-Install the required dependencies: pip install -r requirements.txt

-Ensure that database.csv is up to date (you can download the latest version from https://db-ip.com/db/download/ip-to-asn-lite)

-Start the server: python3 dbs.py

-Replace the server address in the dbcu.py or dbc.sh files if you are using Linux or MacOS.

As input, you can provide a domain name, an IP address, or an AS number. The tool will determine the corresponding AS and display all IP address blocks assigned to that AS.


Example with the Python client:

python3 dbcu.py google.com

python3 dbcu.py 1.1.1.1

python3 dbcu.py AS14524


The example with the bash script is similar:

./dbc.sh google.com
