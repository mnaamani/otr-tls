/*
    Copyright 2012 Brandon Philips (brandon@ifup.org)

    This project is free software released under the MIT/X11 license:

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
*/

/* https://npmjs.org/package/cryptostream */

var crypto = require('crypto');
var util = require('util');
var Stream = require('stream').Stream

function coearseOpts (opts) {
  return 'string' == typeof opts ? {key: opts, algorithm: 'aes-256-ctr'} : opts
}

function CryptoStream(opts, cipher) {
  this._key = opts.key;
  this._cipher = cipher;
  this.inputEncoding = opts.inputEncoding;
  this.outputEncoding = opts.outputEncoding;
  this.readable = this.writable = true
}

util.inherits(CryptoStream, Stream);
exports.CryptoStream = CryptoStream;

CryptoStream.prototype.write = function(data) {
  this.emit("data", this._cipher.update(data, this.inputEncoding, this.outputEncoding));
  return true
}

CryptoStream.prototype.end = function(data) {
  if (data) this.write(data)
  this.emit("data", this._cipher.final(this.outputEncoding))
  this.emit("end");
}

var EncryptStream = function(opts) {
  opts = coearseOpts(opts)
  var cipher = crypto.createCipher(opts.algorithm, opts.key);
  EncryptStream.super_.call(this, opts, cipher);
}

util.inherits(EncryptStream, CryptoStream);
exports.EncryptStream = EncryptStream;

var DecryptStream = function(opts) {
  opts = coearseOpts(opts)
  var decipher = crypto.createDecipher(opts.algorithm, opts.key);
  DecryptStream.super_.call(this, opts, decipher);
}

util.inherits(DecryptStream, CryptoStream);
exports.DecryptStream = DecryptStream;
