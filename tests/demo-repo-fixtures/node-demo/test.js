/**
 * Simple test suite for Node demo fixture.
 */
const assert = require("assert");
const { formatMessage, calculateSum } = require("./index.js");

console.log("Running Node fixture tests...");

assert.strictEqual(formatMessage("Bob"), "Hello, Bob! Powered by SentinelPR.");
assert.strictEqual(calculateSum([1, 2, 3, 4, 5]), 15);
assert.strictEqual(calculateSum([]), 0);

console.log("All Node fixture tests passed successfully!");
