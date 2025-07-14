const fs = require('fs');
const csv = require('csv-parser');
const axios = require('axios');
const ethers = require('ethers');

// Replace with your Etherscan API Key
const ETHERSCAN_API_KEY = '6B2RVAUT24D9SGFS8WZAEUZZUQXK81PJWY';
const inputCsvPath = '../data/transactions.csv';

async function fetchTransactionInput(txHash) {
    const url = `https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=${txHash}&apikey=${ETHERSCAN_API_KEY}`;
    try {
        const response = await axios.get(url);
        return response.data.result ? response.data.result.input : null;
    } catch (error) {
        console.error(`Error fetching transaction ${txHash}:`, error);
        return null;
    }
}

function decodeInput(inputHex, funcInterface, funcName) {
    try {
        const iface = new ethers.Interface(['function ' + funcInterface]);
        return iface.decodeFunctionData(funcName, inputHex);
    } catch (error) {
        console.error(`Error decoding input:`, error);
        return null;
    }
}

async function processCsv() {
    const transactions = [];

    fs.createReadStream(inputCsvPath)
        .pipe(csv())
        .on('data', (data) => transactions.push(data))
        .on('end', async () => {
            const counters = {
                'Verify Merkle': 0,
                'Verify FRI': 0,
                'Register Continuous Memory Page': 0,
                'Verify Proof And Register': 0,
                'Register Continuous Page Batch': 0
            };

            for (const tx of transactions) {
                await new Promise(r => setTimeout(r, 100));
                const method = tx['Method'];
                if (counters.hasOwnProperty(method)) {
                    counters[method]++;
                    const inputHex = await fetchTransactionInput(tx['Transaction Hash']);
                    let decodedInput = {};

                    let filename;
                    if (method === 'Verify Merkle') {
                        filename = `../data/merkle_verify/merkle_verify_${counters[method]}.json`;
                        decodedInput = decodeInput(inputHex, 'verifyMerkle(uint256[] merkleView, uint256[] initialMerkleQueue, uint256 height, uint256 expectedRoot)', 'verifyMerkle');
                        decodedInput = {
                            merkleView: decodedInput[0],
                            initialMerkleQueue: decodedInput[1],
                            height: decodedInput[2],
                            expectedRoot: decodedInput[3]
                        }
                    } else if (method === 'Verify FRI') {
                        filename = `../data/fri_verify/fri_verify_${counters[method]}.json`;
                        decodedInput = decodeInput(inputHex, 'verifyFRI(uint256[] proof, uint256[] friQueue, uint256 evaluationPoint, uint256 friStepSize, uint256 expectedRoot)', 'verifyFRI');
                        decodedInput = {
                            proof: decodedInput[0],
                            friQueue: decodedInput[1],
                            evaluationPoint: decodedInput[2],
                            friStepSize: decodedInput[3],
                            expectedRoot: decodedInput[4]
                        }
                    } else if (method === 'Register Continuous Memory Page') {
                        filename = `../data/memory_page_fact_registry/register_memory_page_${counters[method]}.json`;
                        decodedInput = decodeInput(inputHex, 'registerContinuousMemoryPage(uint256 startAddr, uint256[] values, uint256 z, uint256 alpha, uint256 prime)', 'registerContinuousMemoryPage');
                        decodedInput = {
                            startAddr: decodedInput[0],
                            values: decodedInput[1],
                            z: decodedInput[2],
                            alpha: decodedInput[3],
                            prime: decodedInput[4]
                        }
                    }
                    else if (method === 'Verify Proof And Register') {
                        filename = `../data/gps/verify_proof_and_register_${counters[method]}.json`;
                        decodedInput = decodeInput(inputHex, 'verifyProofAndRegister(uint256[] proofParams, uint256[] proof, uint256[] taskMetadata, uint256[] cairoAuxInput, uint256 cairoVerifierId)', 'verifyProofAndRegister');
                        decodedInput = {
                            proofParams: decodedInput[0],
                            proof: decodedInput[1],
                            taskMetadata: decodedInput[2],
                            cairoAuxInput: decodedInput[3],
                            cairoVerifierId: decodedInput[4]
                        }
                    } else if (method === 'Register Continuous Page Batch') {
                        filename = `../data/memory_page_fact_registry/register_continuous_page_batch_${counters[method]}.json`;
                        decodedInput = decodeInput(inputHex, 'registerContinuousPageBatch((uint256,uint256[],uint256,uint256,uint256)[])', 'registerContinuousPageBatch');
                        decodedInput = {
                            memoryPageEntries: decodedInput[0].map(x => ({
                                startAddr: x[0],
                                values: x[1],
                                z: x[2],
                                alpha: x[3],
                                prime: x[4]
                            }))
                        }
                    }

                    fs.writeFileSync(filename, JSON.stringify(decodedInput, (key, value) =>
                        typeof value === 'bigint'
                            ? value.toString()
                            : value, 2));
                    console.log(`Saved decoded input to ${filename}`);
                }
            }
        });
}

processCsv();
