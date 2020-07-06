#!/usr/bin/env node
'use strict';
const fs = require('fs')
const path = require('path')
const mkdirp = require('mkdirp')
const simplify = require('simplify-sdk')
const provider = require('simplify-sdk/provider')
const utilities = require('simplify-sdk/utilities')
const asciichart = require('asciichart')
const GREEN = '\x1b[32m'
const RED = '\x1b[31m'
const YELLOW = '\x1b[33m'
const WHITE = '\x1b[0m'
const BLUE = '\x1b[34m'
const RESET = '\x1b[0m'
const opName = `SecOps`

var argv = require('yargs')
    .usage('simplify-secops verify|patch|check|metric|snapshot [options]')
    .string('input')
    .alias('i', 'input')
    .describe('input', 'Input file contains function list')
    .default('input', 'functions.csv')
    .string('output')
    .alias('o', 'output')
    .describe('output', 'Output snapshot folder')
    .default('output', '.snapshot')
    .string('baseline')
    .alias('b', 'baseline')
    .describe('baseline', 'baseline snapshot date YYYY-MM-DD')
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
    .string('extended')
    .alias('e', 'extended')
    .describe('extended', 'Extended verification view')
    .string('plot')
    .describe('plot', 'Drawing chart series')
    .demandOption(['i'])
    .demandCommand(1)
    .argv;

var configInputFile = argv.input || 'functions.csv'
var scanOutput = {}
var cmdOPS = (argv._[0] || 'verify').toUpperCase()
var lineIndex = 0
var funcList = []

var files = require('fs').readFileSync(path.resolve(configInputFile), 'utf-8').split(/\r?\n/)
var headers = files[lineIndex++]

function getSnapshotFromFile(snapshotPath) {
    simplify.consoleWithMessage(opName, `${cmdOPS} Snapshot from ${snapshotPath}`)
    if (fs.existsSync(snapshotPath)) {
        return JSON.parse(fs.readFileSync(snapshotPath).toString())
    } else {
        return undefined
    }
}

function takeSnapshotToFile(functionList, outputPath) {
    const outputDir = path.dirname(outputPath)
    if (!fs.existsSync(outputDir)) {
        mkdirp.sync(outputDir);
    }
    fs.writeFileSync(outputPath, JSON.stringify(functionList.map(f => {
        return {
            FunctionName: f.functionInfo.FunctionName,
            CodeSha256: f.functionInfo.CodeSha256,
            LastModified: f.functionInfo.LastModified,
            Version: f.functionInfo.Version,
            Layers: f.Layers.map(layer => {
                return {
                    CodeSha256: layer.Content.CodeSha256,
                    LayerVersionArn: layer.LayerVersionArn,
                    CreatedDate: layer.CreatedDate
                }
            }),
            LogGroup: { LogGroupName: (f.LogGroup || {}).logGroupName }
        }
    }), null, 2), 'utf8');
    simplify.consoleWithMessage(opName, `${cmdOPS} to ${outputPath} \x1b[32m (OK) \x1b[0m`)
}

function analyseOrPatch(args) {
    const { functionInfo, logRetention, customKmsArn, secureFunction, secureLog } = args
    return new Promise((resolve, reject) => {
        const combinedKmsKeyArn = customKmsArn || functionInfo.KMSKeyArn
        if (!functionInfo.KMSKeyArn) {
            if (cmdOPS === 'PATCH') {
                functionInfo.KMSKeyArn = combinedKmsKeyArn
                let functionConfig = {
                    FunctionName: functionInfo.FunctionName
                }
                if (secureFunction /** enabled */ && functionInfo.KMSKeyArn) {
                    functionConfig.KMSKeyArn = functionInfo.KMSKeyArn
                    simplify.updateFunctionConfiguration({
                        adaptor: provider.getFunction(),
                        functionConfig: functionConfig
                    }).then(_ => {
                        simplify.enableOrDisableLogEncryption({
                            adaptor: provider.getKMS(),
                            logger: provider.getLogger(),
                            functionInfo: functionInfo,
                            retentionInDays: logRetention,
                            enableOrDisable: secureLog
                        }).then(function (data) {
                            simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${(logRetention ? `Configured${secureLog ? ' KMS ' : ' '}LogGroup retention for ${logRetention} days!` : `LogGroup is not required to configure`)} \x1b[32m (OK) \x1b[0m`)
                            resolve(args)
                        }).catch(function (err) {
                            reject(`${err}`)
                        })
                    }).catch(function (err) {
                        reject(`${err}`)
                    })
                } else if (secureFunction /** enabled */ && !functionInfo.KMSKeyArn) {
                    simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : You must provide a KMS Custom KeyId! \x1b[31m (ERROR) \x1b[0m`)
                    reject(`Missing KMS KeyId for ${functionInfo.FunctionName}`)
                } else {
                    simplify.enableOrDisableLogEncryption({
                        adaptor: provider.getKMS(),
                        logger: provider.getLogger(),
                        functionInfo: functionInfo,
                        retentionInDays: logRetention,
                        enableOrDisable: secureLog
                    }).then(function (_) {
                        simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${(logRetention ? `Configured${secureLog ? ' KMS ' : ' '}LogGroup retention for ${logRetention} days!` : `LogGroup is not required to configure`)} \x1b[32m (OK) \x1b[0m`)
                        resolve(args)
                    }).catch(function (err) {
                        reject(`${err}`)
                    })
                }
            } else if (cmdOPS === 'CHECK') {
                if (secureFunction) {
                    simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${functionInfo.KMSKeyArn == customKmsArn ? (functionInfo.KMSKeyArn ? `Has already configure with KMS Custom KeyId \x1b[32m[GOOD]\x1b[0m` : `Provide KMS Custom KeyId to setup secure function! \x1b[33m (WARN) \x1b[0m`) : (customKmsArn ? `Has KMS Custom KeyId but not set! \x1b[33m (WARN) \x1b[0m` : `Missing KMS Custom KeyId \x1b[33m (WARN) \x1b[0m`)}`)
                } else {
                    simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${functionInfo.KMSKeyArn == customKmsArn ? `Not require to use KMS Custom KeyId \x1b[32m[GOOD]\x1b[0m` : `Not matching KMS Custom KeyIds \x1b[33m (WARN) \x1b[0m`}`)
                }
                resolve(args)
            } else {
                resolve(args)
            }
        } else {
            if (cmdOPS === 'PATCH') {
                functionInfo.KMSKeyArn = combinedKmsKeyArn ? combinedKmsKeyArn : functionInfo.KMSKeyArn
                /** record new SHA256 Code Here */
                simplify.enableOrDisableLogEncryption({
                    adaptor: provider.getKMS(),
                    logger: provider.getLogger(),
                    functionInfo: functionInfo,
                    retentionInDays: logRetention,
                    enableOrDisable: secureLog
                }).then(function (_) {
                    simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${(logRetention ? `Configured${secureLog ? ' KMS ' : ' '}LogGroup retention for ${logRetention} days!` : `LogGroup is not required to configure`)} \x1b[32m (OK) \x1b[0m`)
                    if (secureFunction) {
                        simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : Configured with KMS Custom KeyId \x1b[32m (OK) \x1b[0m`)
                        args.customKmsArn = functionInfo.KMSKeyArn
                    }
                    resolve(args)
                }).catch(function (err) {
                    reject(`${err}`)
                })
            } else if (cmdOPS === 'CHECK') {
                if (secureFunction) {
                    simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${functionInfo.KMSKeyArn == customKmsArn ? (functionInfo.KMSKeyArn ? `Has already configure with KMS Custom KeyId \x1b[32m[GOOD]\x1b[0m` : `Provide KMS Custom KeyId to setup secure function! \x1b[33m (WARN) \x1b[0m`) : (customKmsArn ? `Has KMS Custom KeyId but not set! \x1b[33m (WARN) \x1b[0m` : `Has configured with KMS but Custom KeyId input is not provided. \x1b[33m (WARN) \x1b[0m`)}`)
                } else {
                    simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName} : ${functionInfo.KMSKeyArn == customKmsArn ? `Has already configure with Custom KMS KeyId \x1b[32m[GOOD]\x1b[0m` : `Not matching KMS Custom KeyIds \x1b[33m (WARN) \x1b[0m`}`)
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
        if (parts.length >= 2) {
            const functionName = parts[2]
            const functionVersion = parts[3] || undefined
            const logRetention = parts[4] || undefined
            const accountId = parts[1]
            if (accountId.indexOf('E') !== -1) {
                simplify.consoleWithMessage(opName, `${cmdOPS} ${functionName} Invalid AccountId number format \x1b[31m (ERROR) \x1b[0m`)
            }
            const customKmsArn = parts[5] ? `arn:aws:kms:${parts[0]}:${accountId}:key/${parts[5]}` : null
            const secureFunction = JSON.parse((parts[6] || 'false').toLowerCase())
            const secureLog = JSON.parse((parts[7] || 'false').toLowerCase())
            if (cmdOPS === 'METRIC') {
                funcList.push({ functionInfo: { FunctionName: `${functionName}` } })
                if (lineIndex >= files.length) {
                    callback && callback(funcList)
                } else {
                    secOpsFunctions(files, callback)
                }
            } else {
                simplify.getFunctionMetaInfos({
                    adaptor: provider.getFunction(),
                    logger: provider.getLogger(),
                    functionConfig: { FunctionName: functionName, Qualifier: functionVersion },
                    silentIs: true
                }).then(function (functionMeta) {
                    const functionInfo = functionMeta.Configuration
                    if (!scanOutput[functionInfo.FunctionName]) {
                        scanOutput[functionInfo.FunctionName] = {}
                    }
                    scanOutput[functionInfo.FunctionName] = functionInfo
                    analyseOrPatch({ functionInfo, logRetention, customKmsArn, secureFunction, secureLog }).then(res => {
                        funcList.push({ ...res, Layers: functionMeta.LayerInfos, LogGroup: functionMeta.LogGroup })
                        if (lineIndex >= files.length) {
                            callback && callback(funcList)
                        } else {
                            secOpsFunctions(files, callback)
                        }
                    }).catch(err => simplify.consoleWithMessage(opName, `${cmdOPS} ${functionInfo.FunctionName}: ${err} \x1b[31m (ERROR) \x1b[0m`))
                }).catch(err => simplify.consoleWithMessage(opName, `${cmdOPS}: ${err} \x1b[31m (ERROR) \x1b[0m`))
            }
        }
    } else {
        callback && callback(funcList)
    }
}

function printMetricCharts(metrics, functionList, pIndex, mIndex) {
    pIndex = pIndex < functionList.length ? pIndex : 0
    const functionName = functionList[pIndex].functionInfo.FunctionName
    const lastHours = parseInt(argv.hours || 3)
    const periodMins = parseInt(argv.periods || 300)/60
    const totalValues = {}
    const series = metrics.MetricDataResults.map(m => {
        const functionId = m.Id.split('_')[1]
        const labelValue = `${m.Label}`
        if (functionId == pIndex) {
            if (!m.Values.length) {
                m.Values.push(0)
            }
            const totalPeriodValue = parseFloat(m.Values.reduce((count, x) => count + x, 0))
            if (!totalValues[labelValue]) totalValues[labelValue] = 0
            if (labelValue === 'Duration' || labelValue === 'Concurrency') {
                totalValues[labelValue] = Math.max(totalValues[labelValue], ...m.Values)
                totalValues[labelValue] = (labelValue === 'Duration' ? (totalValues[labelValue]).toFixed(2) : totalValues[labelValue])
            } else {
                totalValues[labelValue] += totalPeriodValue
            }
            return m.Values
        }
        return undefined
    }).filter(m => m)
    console.log(`\n * (${functionName}): In the last ${lastHours} hours at every ${periodMins} minutes \n`)
    const pColors = [
        asciichart.blue,
        asciichart.red,
        asciichart.green,
        asciichart.yellow,
        asciichart.default
    ]
    console.log(asciichart.plot(series.splice(mIndex || 0, 1), {
        colors: [pColors[mIndex || 0]],
        height: 20
    }))
    const totalLabels = {
        "Invocations": `1- Invocations ${BLUE}BLUE${RESET}`,
        "Errors": `2- Errors ${RED}RED${RESET}`,
        "Duration": `3- Max Duration ${GREEN}GREEN${RESET}`,
        "Concurrency": `4- Max Concurrency ${YELLOW}YELLOW${RESET}`,
        "Throttles": `5- Throttles ${WHITE}WHITE${RESET}`
    }
    console.log(`\n * ${Object.keys(totalValues).map(kv => `${totalLabels[kv]}: ${totalValues[kv]}`).join(' | ')} \n`)
}

function printMetricTable(metrics, functionList) {
    const mData = {}
    const totalValues = {}
    const lastHours = parseInt(argv.hours || 3)
    const periodMins = parseInt(argv.periods || 300)/60
    const table = new utilities.PrintTable()
    metrics.MetricDataResults.map((m, idx) => {
        const data = {}
        const labelValue = `${m.Label}`
        if (!m.Values.length) {
            m.Values.push(0)
        }
        const totalPeriodValue = parseFloat(m.Values.reduce((count, x) => count + x, 0))
        if (!totalValues[labelValue]) totalValues[labelValue] = 0
        if (labelValue === 'Duration' || labelValue === 'Concurrency') {
            totalValues[labelValue] = Math.max(totalValues[labelValue], ...m.Values)
            totalValues[labelValue] = (labelValue === 'Duration' ? totalValues[labelValue].toFixed(2) : totalValues[labelValue])
        } else {
            totalValues[labelValue] += totalPeriodValue
        }
        const functionId = m.Id.split('_')[1]
        const functionName = functionList[functionId].functionInfo.FunctionName
        data[labelValue] = (labelValue === 'Duration' || labelValue === 'Concurrency' ? Math.max(...m.Values) : totalPeriodValue)
        data[labelValue] = (labelValue === 'Duration' ? data[labelValue].toFixed(2) : data[labelValue])
        mData[functionId] = { 'Index': (parseInt(functionId) + 1), 'Function': functionName.truncateLeft(50), ...mData[functionId], ...data }
    })
    let dataRows = Object.keys(mData).map(k => mData[k])
    table.addRows(dataRows)
    table.addRow({ 'Function': `In ${lastHours} hours at every ${periodMins} minutes`, ...totalValues }, { color: 'white_bold' })
    table.printTable()
}

try {
    var config = simplify.getInputConfig({
        Region: argv.region || 'eu-west-1',
        Profile: argv.profile || 'default',
        Bucket: { Name: 'default' }
    })
    provider.setConfig(config).then(function () {
        if (headers.startsWith('Region')) {
            secOpsFunctions(files, function (functionList) {
                if (cmdOPS === 'METRIC') {
                    let startDate = new Date()
                    const lastHours = parseInt(argv.hours || 3)
                    startDate.setHours(startDate.getHours() - (lastHours))
                    simplify.getFunctionMetricData({
                        adaptor: provider.getMetrics(),
                        functions: functionList.map(f => { return { FunctionName: f.functionInfo.FunctionName } }),
                        periods: parseInt(argv.periods || 300),
                        startDate: startDate,
                        endDate: new Date()
                    }).then(metrics => {
                        if (typeof argv.plot === 'undefined') {
                            printMetricTable(metrics, functionList)
                        } else {
                            const indexes = argv.plot.split(',')
                            const pIndex = parseInt(indexes[0] || 1) - 1
                            const mIndex = indexes.length > 0 ? parseInt(indexes[1]) - 1 : 0
                            printMetricCharts(metrics, functionList, pIndex < 0 ? 0 : pIndex, mIndex < 0 ? 0 : mIndex)
                        }
                    }).catch(err => simplify.consoleWithMessage(opName, `${err}`))
                } else if (cmdOPS === 'VERIFY') {
                    let isSimpleView = true
                    if (typeof argv.extended !== 'undefined') {
                        isSimpleView = false
                    }
                    const snapshotList = getSnapshotFromFile(path.resolve(argv.output, `${argv.baseline || '$LATEST'}.json`))
                    const outputTable = functionList.map((func, idx) => {
                        const snapshot = snapshotList ? snapshotList.find(f => f.FunctionName === func.functionInfo.FunctionName) : { Layers: [] }
                        var areLayersValid = snapshotList ? true : false
                        snapshot && snapshot.Layers.map(layer => {
                            const layerInfo = func.Layers.find(info => info.LayerVersionArn === layer.LayerVersionArn)
                            if (layerInfo && layerInfo.Content.CodeSha256 !== layer.CodeSha256) {
                                areLayersValid = false
                            }
                        })
                        func.LogGroup = func.LogGroup || {}
                        func.functionInfo = func.functionInfo || {}
                        const basicView = {
                            Index: idx + 1,
                            FunctionName: func.functionInfo.FunctionName.truncateLeft(50),
                            CodeSha256: `${func.functionInfo.CodeSha256.truncateLeft(5, '')} (${func.functionInfo.CodeSha256 === (snapshot || {}).CodeSha256 ? 'OK' : 'NOK'})`,
                            Layers: `${func.Layers.length} (${areLayersValid ? 'OK' : 'NOK'})`,
                            LogRetention: `${func.LogGroup.retentionInDays || '-'} / ${func.logRetention || '-'} (${func.LogGroup.retentionInDays == func.logRetention ? 'OK' : 'PATCH'})`,
                            EncryptionKey: (func.customKmsArn ? `KMS ${func.functionInfo.KMSKeyArn === func.customKmsArn ? '(OK)' : '(PATCH)'}` : `${func.functionInfo.KMSKeyArn ? 'KMS' : '-'} ${func.functionInfo.KMSKeyArn === func.customKmsArn ? '(OK)' : '(PATCH)'}`).truncateLeft(13),
                            SecureFunction: func.secureFunction ? (func.functionInfo.KMSKeyArn ? 'YES (OK)' : 'YES (PATCH)') : (func.functionInfo.KMSKeyArn ? 'NO (PATCH)' : 'NO (OK)'),
                            SecureLog: func.secureLog ? (func.LogGroup.kmsKeyId ? 'YES (OK)' : 'YES (PATCH)') : (func.LogGroup.kmsKeyId ? 'NO (PATCH)' : 'NO (OK)')
                        }
                        const extendedView = {
                            Index: idx + 1,
                            FunctionName: func.functionInfo.FunctionName.truncateLeft(50),
                            LastModified: utilities.formatTimeSinceAgo(new Date(func.functionInfo.LastModified)),
                            State: func.functionInfo.State,
                            CodeSize: `${utilities.formatBytesToKBMB(parseInt(func.functionInfo.CodeSize))}`,
                            MemorySize: `${utilities.formatBytesToKBMB(parseInt(func.functionInfo.MemorySize) * 1024 * 1024)}`,
                            Timeout: `${func.functionInfo.Timeout} s`,
                            Runtime: func.functionInfo.Runtime
                        }
                        return isSimpleView ? basicView : extendedView
                    })
                    utilities.printTableWithJSON(outputTable)
                } else if (cmdOPS === 'SNAPSHOT') {
                    takeSnapshotToFile(functionList, path.resolve(argv.output, `${utilities.getDateToday()}.json`))
                    takeSnapshotToFile(functionList, path.resolve(argv.output, `$LATEST.json`))
                }
            })
        }
    })
} catch (err) {
    simplify.finishWithErrors(`${opName}-LoadConfig`, err)
}
