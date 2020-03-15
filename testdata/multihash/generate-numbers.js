const crypto = require("crypto");

const MIN_LENGTH = 1;
const MAX_LENGTH = 20;
const COUNT = 10000;

for (let iteration = 0; iteration < COUNT; iteration++) {
    const length_bytes = crypto.randomBytes(4);
    const length = MIN_LENGTH + (length_bytes.readUInt32BE(0) % (MAX_LENGTH - MIN_LENGTH));

    const value_bytes = crypto.randomBytes(length);
    const value_hex = value_bytes.toString("hex");
    console.log(value_hex);
}
