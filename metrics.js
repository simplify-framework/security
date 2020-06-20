const AWS = require('aws-sdk')
const path = require('path')

var argv = require('yargs')
    .usage('simplify-secops metrics [options]')
    .string('input')
    .alias('i', 'input')
    .describe('input', 'Input file contains function list')
    .default('input', 'functions.csv|deployment-input.json')
    .string('type')
    .describe('type', 'Type of input file [csv|openapi|graphql]')
    .alias('t', 'type')
    .default('type', 'csv')
    .string('profile')
    .describe('profile', 'AWS Profile configuration')
    .alias('p', 'profile')
    .default('profile', 'default')
    .string('region')
    .describe('region', 'AWS Specific Region')
    .alias('r', 'region')
    .default('region', 'eu-west-1')
    .demandOption(['i'])
    .demandCommand(1)
    .argv;

var cloudwatch = new AWS.CloudWatch({ apiVersion: '2010-08-01', region: argv.region });

function getLambdaMetrics(listFunc, metricName, startDate, endDate, periods) {
    return new Promise((resolve, reject) => {
        var params = {
            EndTime: endDate || new Date(),
            MetricName: metricName, /* Duration - Invocations - Throttles - Errors - ConcurrentExecutions */
            Namespace: 'AWS/Lambda', /* required */
            Period: periods || 10, /* 12 x (5 minutes) */
            StartTime: startDate,
            Dimensions: listFunc.map(func => {
                if (func.monitorMetrics) {
                    return {
                        Name: 'FunctionName',
                        Value: `${func.FunctionName}`
                    }
                }
            }).filter(func => func != undefined),
            Statistics: [
                "SampleCount",
                "Average",
                "Sum",
                "Minimum",
                "Maximum",
                /* more items */
            ]
        };
        cloudwatch.getMetricStatistics(params, function (err, data) {
            err ? reject(err) : resolve(data)
        });
    })
}