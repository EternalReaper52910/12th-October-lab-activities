/**
 * DevSecOps Lab - Core Calculator Business Logic Engine
 */

function add(a, b) {
    if (typeof a !== 'number' || typeof b !== 'number') {
        throw new TypeError('Inputs must be numbers');
    }
    return a + b;
}

function subtract(a, b) {
    if (typeof a !== 'number' || typeof b !== 'number') {
        throw new TypeError('Inputs must be numbers');
    }
    return a - b;
}

function multiply(a, b) {
    if (typeof a !== 'number' || typeof b !== 'number') {
        throw new TypeError('Inputs must be numbers');
    }
    return a * b;
}

function divide(a, b) {
    if (typeof a !== 'number' || typeof b !== 'number') {
        throw new TypeError('Inputs must be numbers');
    }
    if (b === 0) {
        throw new RangeError('Division by zero is not allowed');
    }
    return a / b;
}

module.exports = {
    add,
    subtract,
    multiply,
    divide
};
