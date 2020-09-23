# python-aws-terminate-ec2
Used to decommission instances.

Testing in Python virtual environment using python version 3.6

## Getting Started

### Virtual environment
python3.6 -m venv env
source env/bin/activate
pip install --upgrade awscli
pip install --upgrade pip
pip install --upgrade boto3

### Environment Variables
To ensure the code can easily be re-used I have set all the key elements as variables. These can also be defined as variables in any automation software.

Key                  | Value
---------------------|----------------------
dry_run | True or False - if yes the code will only check for access
search_tag | Tag to search for instances, e.g. Name
search_value | Value in search_tag to search for instances
snap_prefix | Snapshot description
arole | Role to assume across accounts
accounts | list of accounts to process using above role e.g ['0000000000000','1111111111111','2222222222222222','333333333333333333']

## Process Flow
1. For each account listed
2. Retrieve instance details from instances which fulfil the filter rules
3. For each instance
4. Shutdown if running
5. Change EBS deleteontermination to True if False
6. Snapshot EBS volume(s)
7. Terminate Instance(s)

### Known issues
None

### Completed enhancements
1. Setup to use tags instead of input file
2. Setup to use a role rather than AWS CLI credentials.
3. Configure to use an array of accounts.
4. remove the counts and instead use the cli wait commands (new post code writing)
5. Rewrite in python

### Planned enhancements
None presently

## Author
**Dave Hart**
[link to blog!](https://davehart.co.uk)

