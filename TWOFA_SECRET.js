const speakeasy = require('speakeasy');
console.log(speakeasy.generateSecret({ length: 20 }).base32);