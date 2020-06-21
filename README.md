# simplify-secops - Security & Operation

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
- Examine deployed functions against your list of definitions
    + `simplify-secops -p simplify-eu status`
- Record a snapshot with current state of functions
    + `simplify-secops -p simplify-eu snapshot`
- Examine deployed functions with a specified snapshot date
    + `simplify-secops -p simplify-eu status -b 2020-06-21`
- Check deployed functions and functions' parameters
    + `simplify-secops -p simplify-eu check`
- Patch deployed functions with functions' parameters
    + `simplify-secops -p simplify-eu patch`
- Monitor deployed functions with standard metrics
    eg: options for last 12 hours with sample in every 300 seconds
    + `simplify-secops -p simplify-eu metric -t 300 -h 12`

### Example of (security) metrics:

-------------------------------------------------------------------------------------------------
|   CodeSize |  Timeout |  Layers | LogRetention | EncryptionKey | SecureFunction |   SecureLog |
|------------|----------|---------|--------------|---------------|----------------|-------------|
|  276 bytes |   3 secs | 1 (NOK) | 90 / 90 (OK) |      KMS (OK) |       YES (OK) |     NO (OK) |
| 3124 bytes | 180 secs | 1 (NOK) | 90 / 90 (OK) |  Default (OK) |    YES (PATCH) | YES (PATCH) |
| 6198 bytes | 210 secs | 1 (NOK) | 90 / 90 (OK) |  Default (OK) |        NO (OK) |     NO (OK) |
|-----------------------------------------------------------------------------------------------|

### Example of (operation) metrics:

-----------------------------------------------------------------------------------------------------
|           Function |  DateTime (12 hours ago) | Invocations |  Errors |    Duration | Concurrency |
|--------------------|--------------------------|-------------|---------|-------------|-------------|
|  test-function-foo | 2020-06-21T21:00:26.675Z |     120 / 0 |   4 / 0 |  321.43 avg |      31 / 0 |
| foo-secret-manager | 2020-06-21T18:33:00.000Z |       1 / 1 |   0 / 0 | 1161.00 avg |       1 / 1 |
|   foo-user-manager | 2020-06-21T18:54:00.000Z |       1 / 1 |   0 / 0 |  938.53 avg |       1 / 1 |
|   foo-user-manager | 2020-06-21T18:48:00.000Z |             |   0 / 0 |             |             |
|   foo-user-manager | 2020-06-21T18:47:00.000Z |             |   0 / 0 |             |             |
|---------------------------------------------------------------------------------------------------|