# README

vulnprioritize is a script that helps proritize vulnerabilities using the CVSS, KEV, EPSS, exploitability likelihood and malware exploitability as a base for risk based prioritization.

Right now it supports the following vendor reports:
- Tenable One (CSV)

## How to use it

First, download the source code from the repository:

```bash
git clone https://github.com/leuribe2/vulnprioritize.git
cd vulnprioritize
```

After that, create the virtual environment and install the requirements:

```python
python3 -m venv .venv
source .venv/bin/activate
pip3 install -r requirements.txt
````

Now place into the **data** folder the Tenable One CSV vulnerabilities named tenable_one_csv.csv and run the following command:

```python
python3 checker.py
````

Now you should get an **output.txt** file