## Development

Get started contributing to this provider:

1. Run `python3 -m venv .venv` to create a virtual environment.
2. Activate your virtual environment using `source .venv/bin/activate`
3. Run `pip install commonfate-provider` to install the Common Fate Provider library.
4. Run `pip freeze > requirements.txt` to save the dependencies.

### Development roles

Create a development CloudWatch read role:

```bash
# run from the profile that has the CloudWatch logs you want to grant access to
python dev_role.py create-role --role cloudwatch-read --account-id=YOUR_CF_ACCOUNT_ID
```

```bash
# run from the profile that has the AWS SSO instance
python dev_role.py create-role --role aws-sso-provision --account-id=YOUR_CF_ACCOUNT_ID
```
