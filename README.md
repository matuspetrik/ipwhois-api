# ipwhois-api

This application reads IP addresses from a file, fetches their information from the ipinfo.io API using a bearer token, and writes the results to an output file. It also retrieves CIDR information for each IP address using the IPWhois library.

# Usage

## Download and initialize
```
git clone git@github.com:matuspetrik/ipwhois-api.git
cd ipwhois-api
source .venv/bin/activate
pip install -r Files/requirements.txt
```

## Update the variables file
```
cp Files/input-variables.yml.template Files/input-variables.yml
```
Note: ipinfo.io account with valid bearer token is required

## Update the IPs file
```
vim Files/one-ip-per-line.txt
```

## Run
```
python main.py
```