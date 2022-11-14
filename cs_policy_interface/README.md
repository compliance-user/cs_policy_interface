CS Policy Interface
==============

Python client for CS Policy Interface.


Installation
------------

First of all, clone the repo and go to the repo directory:

    git clone https://review.corestack.in/cs_policy_interface.git
    cd cs_policy_interface
    pip install -r requirements.txt

Then just run:

    python setup.py install


Dependencies
------------

To install Microsoft ODBC 17 Driver follow the steps specified in following link:

    https://docs.microsoft.com/en-us/sql/connect/odbc/linux-mac/installing-the-microsoft-odbc-driver-for-sql-server?view=sql-server-ver15

In case of CentOS install pyodbc from yum instead of pip:

    yum install pyobdc