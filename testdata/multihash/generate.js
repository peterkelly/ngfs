const crypto = require("crypto");
const fs = require("fs");
const multibase = require("multibase");
const path = require("path");

const MIN_LENGTH = 1;
const MAX_LENGTH = 20;
const COUNT = 10000;

function generate_numbers() {
    const numbers = [];

    for (let iteration = 0; iteration < COUNT; iteration++) {
        const lengthBytes = crypto.randomBytes(4);
        const length = MIN_LENGTH + (lengthBytes.readUInt32BE(0) % (MAX_LENGTH - MIN_LENGTH));
        const valueBytes = crypto.randomBytes(length);
        numbers.push(valueBytes);
    }
    return numbers;
}

function writeNumbers(numbers, outFilename) {
    const lines = [];
    for (const num of numbers) {
        lines.push(num.toString("hex"));
    }
    fs.writeFileSync(outFilename, lines.join("\n") + "\n");
    console.log("Wrote " + outFilename);
}

function writeNumberHashes(numbers, code, outFilename) {
    const lines = [];
    const maxLineLength = MAX_LENGTH * 2;
    for (const bytes of numbers) {
        const hex = bytes.toString("hex");
        const encoded = multibase.encode(code, bytes);
        lines.push(hex.padEnd(maxLineLength) + " " + encoded.toString("utf-8"));
    }
    fs.writeFileSync(outFilename, lines.join("\n") + "\n");
    console.log("Wrote " + outFilename);
}

function main() {
    if (process.argv.length < 3) {
        console.error("Usage: generate-multihash.js OUTDIR");
        process.exit(1);
    }

    const outDir = process.argv[2];
    const numbers = generate_numbers();

    writeNumbers(numbers, path.join(outDir, "numbers.txt"));

    for (const name of multibase.names) {
        if (name === "base1")
            continue;
        writeNumberHashes(numbers, name, path.join(outDir, name + ".txt"));
    }
}

main();
