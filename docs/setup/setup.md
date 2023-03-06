

---
title: Find the API_KEY of your company
configFields:
  - api_key
---

### Using the AWS CLI

If you have the AWS CLI installed and can access the account that your AWS SSO instance is deployed to, run the following command to retrieve details about the instance:

```bash
❯ aws sso-admin list-instances
{
    "Instances": [
        {
            "InstanceArn": "arn:aws:sso:::instance/ssoins-1234567890",
            "IdentityStoreId": "d-1234567890"
        }
    ]
}
```

The **InstanceArn** value in the CLI output should be provided as the **instanceArn** parameter when configuring the provider.
