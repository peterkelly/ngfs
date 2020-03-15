const fs = require("fs");
const bs58 = require("bs58");

function main() {
    if (process.argv.length < 3) {
        console.log("Usage: generate-base58.js INFILE");
        process.exit(1);
    }

    const filename = process.argv[2];
    const hash = process.argv[3];

    const numbersContent = fs.readFileSync(filename, "utf-8");
    const numbersLines = numbersContent.replace(/\n$/, "").split("\n");

    let maxLineLength = 40;
    // for (const line of numbersLines) {
    //     maxLineLength = Math.max(maxLineLength, line.length);
    // }

    let index = 0;
    for (const line of numbersLines) {
        const bytes = Buffer.from(line, "hex");
        const encoded = bs58.encode(bytes);
        console.log(line.padEnd(maxLineLength) + " z" + encoded);
        index++;
    }
}

main();
