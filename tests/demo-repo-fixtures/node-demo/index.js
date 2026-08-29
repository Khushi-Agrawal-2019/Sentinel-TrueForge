/**
 * Sample Node.js application for SentinelPR demonstration.
 */

function formatMessage(name) {
  return `Hello, ${name}! Powered by SentinelPR.`;
}

function calculateSum(numbers) {
  if (!Array.isArray(numbers)) return 0;
  return numbers.reduce((acc, curr) => acc + curr, 0);
}

module.exports = { formatMessage, calculateSum };
