const fs = require("fs");
const multibase = require("multibase");

function main() {
    if (process.argv.length < 4) {
        console.log("Usage: generate-multihash.js INFILE HASH");
        console.log();
        console.log("Supported hashes:");
        for (const name of multibase.names) {
            console.log("    " + name);
        }
        process.exit(1);
    }

    const filename = process.argv[2];
    const hash = process.argv[3];

    const numbersContent = fs.readFileSync(filename, "utf-8");
    const numbersLines = numbersContent.replace(/\n$/, "").split("\n");

    let maxLineLength = 0;
    for (const line of numbersLines) {
        maxLineLength = Math.max(maxLineLength, line.length);
    }

    let index = 0;
    for (const line of numbersLines) {
        const bytes = Buffer.from(line, "hex");
        const encoded = multibase.encode(hash, bytes);
        console.log(line.padEnd(maxLineLength) + " " + encoded.toString("utf-8"));
        index++;
    }
}

main();
