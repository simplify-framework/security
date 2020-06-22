# Security & Operation

![NPM Downloads](https://img.shields.io/npm/dw/simplify-secops)
![Package Version](https://img.shields.io/github/package-json/v/simplify-framework/security?color=green)

This project aims to cover SecOps for AWS Lambda serverless first. To use this package, install it as a global comand line tool:

`npm install -g simplify-secops`


### Define a function list in CSV format:
```csv
Region,Account,FunctionName,Version,LogRetention,KMS,SecureFunction,SecureLog
eu-west-1,123456789012,test-function-kms,,90,1,TRUE,FALSE
```

### Command Line Support:
- Verify deployed functions against your list of definitions
    + `simplify-secops -p simplify-eu verify -i functions.csv`
- Record a snapshot with current state of functions
    + `simplify-secops -p simplify-eu snapshot -i functions.csv -o .snapshot`
- Verify deployed functions with a specified snapshot date
    + `simplify-secops -p simplify-eu verify -i functions.csv -b 2020-06-21`
- Check deployed functions and functions' parameters
    + `simplify-secops -p simplify-eu check -i functions.csv`
- Patch deployed functions with functions' parameters
    + `simplify-secops -p simplify-eu patch -i functions.csv`
- Monitor deployed functions with standard simple view metrics
    eg: options for last 12 hours with sample in every 300 seconds
    + `simplify-secops -p simplify-eu metric -i functions.csv -t 300 -h 12 --simple`

### Example of (security) metrics:

------------------------------------------------------------------------------------------------------------
|           Function |  CodeSHA256 |  Layers | LogRetention | EncryptionKey | SecureFunction |   SecureLog |
|--------------------|-------------|---------|--------------|---------------|----------------|-------------|
|  test-function-foo | 9AD72= (OK) | 1 (NOK) | 90 / 90 (OK) |      KMS (OK) |       YES (OK) |     NO (OK) |
| foo-secret-manager | f4Bfa= (OK) | 1 (NOK) | 90 / 90 (OK) |  Default (OK) |    YES (PATCH) | YES (PATCH) |
|   foo-user-manager | bcBa1= (OK) | 1 (NOK) | 90 / 90 (OK) |  Default (OK) |        NO (OK) |     NO (OK) |


### Example of (operation) metrics:

--------------------------------------------------------------------------------
|                 Function | Invocations |  Errors |    Duration | Concurrency |
|--------------------------|-------------|---------|-------------|-------------|
|        test-function-foo |         120 |       4 |      321.43 |          31 |
|       foo-secret-manager |           1 |       0 |     1161.00 |           1 |
|         foo-user-manager |           1 |       0 |      938.53 |           1 |
|   Statistics in 12 hours |         **122** |       **4** |     **1161.00** |        **33** |

