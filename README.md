# Security & Operation

![NPM Downloads](https://img.shields.io/npm/dw/simplify-security)
![Package Version](https://img.shields.io/github/package-json/v/simplify-framework/security?color=green)

This project aims to cover SecOps for AWS Lambda serverless first. To use this package, install it as a global comand line tool:

`npm install -g simplify-security`


### Define a function list in CSV format:
```csv
Region,Account,FunctionName,Version,LogRetention,KMS,SecureFunction,SecureLog
eu-west-1,123456789012,test-function-kms,,90,1,TRUE,FALSE
```

### Command Line Support:
- Verify deployed functions against your list of definitions
    + `simplify-security -p simplify-eu verify -i functions.csv --simple`
- Record a snapshot with current state of functions
    + `simplify-security -p simplify-eu snapshot -i functions.csv -o .snapshot`
- Verify deployed functions with a specified snapshot date
    + `simplify-security -p simplify-eu verify -i functions.csv -b 2020-06-21`
- Check deployed functions and functions' parameters
    + `simplify-security -p simplify-eu check -i functions.csv`
- Patch deployed functions with functions' parameters
    + `simplify-security -p simplify-eu patch -i functions.csv`
- Monitor deployed functions with standard simple view metrics
  
  eg: options for last 12 hours with sample in every 5 mins (5*60 = 300) seconds
    + `simplify-security -p simplify-eu metric -i functions.csv -t 300 -h 12`
  
  eg: drawing the function data with index=1 and INVOCATIONS (1) as a timeseries chart
    + `simplify-security -p simplify-eu metric -i functions.csv -t 300 -h 12 --plot 1,1`

       2.00 ┼╮ 
       1.95 ┤│ 
       1.90 ┤│ 
       1.85 ┤│ 
       1.80 ┤│ 
       1.75 ┤│ 
       1.70 ┤│ 
       1.65 ┤│ 
       1.60 ┤│ 
       1.55 ┤│ 
       1.50 ┤│ 
       1.45 ┤│ 
       1.40 ┤│ 
       1.35 ┤│ 
       1.30 ┤│ 
       1.25 ┤│ 
       1.20 ┤│ 
       1.15 ┤│ 
       1.10 ┤│ 
       1.05 ┤│ 
       1.00 ┤╰ 
    
    * 1- Invocations BLUE: 3 | 2- Errors RED: 0 | 3- Max Duration GREEN: 938.53 | 4- Max Concurrency YELLOW: 2 | 5- Throttles WHITE: 4 

### Example of (security) metrics:

-------------------------------------------------------------------------------------------------------------------
| Index |           Function |  CodeSHA256 | Layers | LogRetention | EncryptionKey | SecureFunction |   SecureLog |
|-------|--------------------|-------------|--------|--------------|---------------|----------------|-------------|
|     1 |  test-function-foo | 9AD72= (OK) | 1 (OK) | 90 / 90 (OK) |      KMS (OK) |       YES (OK) |     NO (OK) |
|     2 | foo-secret-manager | f4Bfa= (OK) | 1 (OK) | 90 / 90 (OK) |  Default (OK) |    YES (PATCH) | YES (PATCH) |
|     3 |   foo-user-manager | bcBa1= (OK) | 1 (OK) | 90 / 90 (OK) |  Default (OK) |        NO (OK) |     NO (OK) |


### Example of (operation) metrics:

-----------------------------------------------------------------------------------------
| Index |                 Function | Invocations |  Errors |    Duration | Concurrency |
|-------|--------------------------|-------------|---------|-------------|-------------|
|     1 |        test-function-foo |         120 |       4 |      321.43 |          31 |
|     2 |       foo-secret-manager |           1 |       0 |     1161.00 |           1 |
|     3 |         foo-user-manager |           1 |       0 |      938.53 |           1 |
|       |   Statistics in 12 hours |         **122** |       **4** |     **1161.00** |        **33** |

