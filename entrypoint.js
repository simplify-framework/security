#!/usr/bin/env node
'use strict';

const path = require('path')
const simplify = require('simplify-sdk')
const provider = require('simplify-sdk/provider')
const utilities = require('simplify-sdk/utilities')
const CBEGIN = '\x1b[32m'
const CERROR = '\x1b[31m'
const CRESET = '\x1b[0m'
const CDONE = '\x1b[37m'
const opName = `SecOps`

var argv = require('yargs')
    .usage('simplify-secops status|patch|check|metric [options]')
    .string('input')
    .alias('i', 'input')
    .describe('input', 'Input file contains function list')
    .default('input', 'functions.csv')
    .string('hours')
    .describe('hours', 'How many hours since now eg: 12 - last 12 hours')
    .alias('h', 'hours')
    .string('periods')
    .describe('periods', 'Time resolution periods eg: 5 10 30 60 N*60 in seconds')
    .alias('t', 'periods')
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

var configInputFile = argv.input || 'functions.csv'
var scanOutput = {}
var cmdOPS = (argv._[0] || 'status').toUpperCase()
var lineIndex = 0
var funcList = []

var files = require('fs').readFileSync(path.join(__dirname, configInputFile), 'utf-8').split(/\r?\n/)
var headers = files[lineIndex++]

function analyseOrPatch(args) {
    const { functionInfo, logRetention, customKmsArn, secureFunction, secureLog } = args
    return new Promise((resolve, reject) => {
        functionInfo.KMSKeyArn = functionInfo.KMSKeyArn || customKmsArn
        if (functionInfo.KMSKeyArn) {
            if (cmdOPS === 'PATCH') {
                let functionConfig = {
                    FunctionName: functionInfo.FunctionName
                }
                if (secureFunction /** enabled */) {
                    functionConfig.KMSKeyArn = functionInfo.KMSKeyArn
                }
                simplify.updateFunctionConfiguration({
                    adaptor: provider.getFunction(),
                    functionConfig: functionConfig
                }).then(functionOutput => {
                    /** record new SHA256 Code Here */
                    simplify.enableOrDisableLogEncryption({
                        adaptor: provider.getKMS(),
                        logger: provider.getLogger(),
                        functionInfo: functionInfo,
                        retentionInDays: logRetention,
                        enableOrDisable: secureLog
                    }).then(function (data) {
                        console.log(`${CBEGIN}Simplify${CRESET} | \x1b[32m[DONE]\x1b[0m ${cmdOPS} ${functionInfo.FunctionName} : Configured secure logs with ${logRetention} days!`)
                        resolve(args)
                    }).catch(function (err) {
                        reject(`${err}`)
                    })
                }).catch(function (err) {
                    reject(`${err}`)
                })
            } else if (cmdOPS === 'CHECK') {
                console.log(`${CBEGIN}Simplify${CRESET} | \x1b[32m[GOOD]\x1b[0m ${cmdOPS} ${functionInfo.FunctionName} : ${functionInfo.KMSKeyArn ? 'Has already configure with KMS Custom Key' : 'Provide a KMS Custom Key to apply a PATCH'}!`)
                resolve(args)
            } else {
                resolve(args)
            }
        } else {
            if (cmdOPS === 'PATCH') {
                if (secureFunction) {
                    console.error(`${CBEGIN}Simplify${CRESET} | \x1b[31m[ERROR]\x1b[0m ${cmdOPS} ${functionInfo.FunctionName} : Provide a KMS Custom Key ARN!`)
                }
                resolve(args)
            } else if (cmdOPS === 'CHECK') {
                if (secureFunction) {
                    console.log(`${CBEGIN}Simplify${CRESET} | \x1b[33m[WARN]\x1b[0m ${cmdOPS} ${functionInfo.FunctionName} : Provide a KMS Custom Key ARN!`)
                }
                resolve(args)
            } else {
                resolve(args)
            }
        }
    })
}
const secOpsFunctions = function (files, callback) {
    const currentLine = files[lineIndex++]
    if (currentLine) {
        const parts = currentLine.split(',')
        if (parts.length >= 6) {
            const functionArn = `arn:aws:lambda:${parts[0]}:${parts[1]}:function:${parts[2]}`
            const logRetention = parts[3] || 90
            const customKmsArn = parts[4] ? `arn:aws:kms:${parts[0]}:${parts[1]}:key/${parts[4]}` : undefined
            const secureFunction = JSON.parse((parts[5] || 'false').toLowerCase())
            const secureLog = JSON.parse((parts[6] || 'false').toLowerCase())
            simplify.getFunctionMetaInfos({
                adaptor: provider.getFunction(),
                functionConfig: { FunctionName: functionArn }
            }).then(function (functionMeta) {
                const functionInfo = functionMeta.Configuration
                if (!scanOutput[functionInfo.FunctionName]) {
                    scanOutput[functionInfo.FunctionName] = {}
                }
                scanOutput[functionInfo.FunctionName] = functionInfo
                analyseOrPatch({ functionInfo, logRetention, customKmsArn, secureFunction, secureLog }).then(res => {
                    funcList.push({ ...res, Layers: functionMeta.LayerInfos })
                    if (lineIndex >= files.length) {
                        callback && callback(funcList)
                    } else {
                        secOpsFunctions(files, callback)
                    }
                })
            }).catch(err => console.log(`${CBEGIN}Simplify${CRESET} | ERROR: ${err}`))
        }
    } else {
        callback && callback(funcList)
    }
}

try {
    var config = simplify.getInputConfig({
        Region: argv.region || 'eu-west-1',
        Profile: argv.profile || 'default',
        Bucket: { Name: 'default' }
    })
    provider.setConfig(config).then(function () {
        if (headers.startsWith('Region')) {
            secOpsFunctions(files, function (list) {
                if (cmdOPS === 'METRIC') {
                    let startDate = new Date()
                    startDate.setHours(startDate.getHours() - (parseInt(argv.hours || 12)))
                    simplify.getFunctionMetricData({
                        adaptor: provider.getMetrics(),
                        functions: list.map(l => { return { FunctionName: l.FunctionName } }),
                        periods: parseInt(argv.periods || 300),
                        startDate: startDate,
                        endDate: new Date()
                    }).then(metrics => {
                        metrics.MetricDataResults.map(m => {
                            let mData = []
                            if (!m.Values.length) {
                                mData.push({
                                    Label: m.Label,
                                    Timestamp: new Date().toISOString(),
                                    Value: '0'
                                })
                            } else {
                                for (let i = 0; i < m.Values.length; i++) {
                                    mData.push({
                                        Label: m.Label,
                                        Timestamp: m.Timestamps[i],
                                        Value: m.Values[i]
                                    })
                                }
                            }
                            utilities.printTableWithJSON(mData)
                        })
                    }).catch(err => console.error(`${err}`))
                } else {
                    const outputTable = list.map(func => {
                        return {
                            FunctionName: func.functionInfo.FunctionName.truncateRight(20),
                            LastModified: new Date(func.functionInfo.LastModified).toISOString(),
                            State: func.functionInfo.State,
                            CodeSize: `${func.functionInfo.CodeSize} bytes`,
                            Timeout: `${func.functionInfo.Timeout} secs`,
                            CodeSha256: `${func.functionInfo.CodeSha256.truncateLeft(5)} (OK)`,
                            Layers: `${func.Layers.length} (OK)`,
                            LogRetention: `${func.logRetention} days`,
                            EncryptionMode: (func.customKmsArn ? 'KMS': 'Default').truncateLeft(12),
                            SecureFunction: func.secureFunction ? (func.functionInfo.KMSKeyArn ? 'YES (OK)' : 'YES (PATCH)') : (func.functionInfo.KMSKeyArn ? 'NO (PATCH)' : 'NO (OK)'),
                            SecureLog: func.secureLog ? (func.functionInfo.KMSKeyArn ? 'YES (OK)' : 'YES (PATCH)') : (func.functionInfo.KMSKeyArn ? 'NO (PATCH)' : 'NO (OK)')
                        }
                    })
                    utilities.printTableWithJSON(outputTable)
                }
            })
        }
    })
} catch (err) {
    simplify.finishWithErrors(`${opName}-LoadConfig`, err)
}