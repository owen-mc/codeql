import "dummy";

let capturedWrite = 0; // $ capturedWrite=capturedWrite

function readCaptured() {
  return capturedWrite; // $ noCapturedWrite=capturedWrite
}

function writeCaptured() {
  capturedWrite = 1; // $ capturedWrite=capturedWrite
  ++capturedWrite; // $ capturedWrite=capturedWrite
  capturedWrite += 1; // $ capturedWrite=capturedWrite
}

function uncapturedWrites() {
  let uncapturedWrite = 0; // $ noCapturedWrite=uncapturedWrite
  return uncapturedWrite++; // $ noCapturedWrite=uncapturedWrite
}

globalWrite = 1; // $ noCapturedWrite=globalWrite
use(globalWrite); // $ noCapturedWrite=globalWrite

const { capturedPattern } = input; // $ capturedWrite=capturedPattern
function readCapturedPattern() {
  return capturedPattern; // $ noCapturedWrite=capturedPattern
}
