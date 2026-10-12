/**
 * DevSecOps Lab Application Entry Point
 * Exports calculator arithmetic functions and Express server instance
 */

const calculator = require('./calculator');
const serverApp = require('./server');

module.exports = {
    ...calculator,
    serverApp
};
