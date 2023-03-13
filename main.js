import hmacSHA512 from 'crypto-js/hmac-sha256.js';
import fetch from 'node-fetch';
import {v4} from "uuid";
import dotenv from "dotenv";

dotenv.config();

const ENDPOINT = 'https://risk.verichains.xyz/api/v1/address-security';

var appid = process.env.APP_ID;
var appSecret = process.env.APP_SECRET;

var timestamp = new Date().getTime();
var nonce = v4().replace(/-/g, '');


async function getRiskDetailForAddress(address) {
  const body = {"address": address, "chain_id": 56}

  const msg = appid + ";" + timestamp + ";" + nonce + ";" +"POST;/api/v1/address-security;" + JSON.stringify(body);
  var hash = hmacSHA512(msg, appSecret);
  var signature = hash.toString();
  
  const result = JSON.stringify(await(await fetch(ENDPOINT, {
    body: JSON.stringify(body),
    headers: {
      "Content-Type": "application/json",
      "X-Signature-Appid": appid,
      "X-Signature-Nonce": nonce,
      "X-Signature-Signature": signature,
      "X-Signature-Timestamp": timestamp
    },
    method: "POST"
  })).json())
  return result;
}

const ADDRESSES = [
  '0x8F0528cE5eF7B51152A59745bEfDD91D97091d2F', //{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":100,"risk_type":[],"risk_details":[],"scanned_ts":1678701902}}
  '0x57282282a6cbd3658576883eb6674e339609c714', //{"status":"OK","code":"000000000","data":{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":10,"risk_type":["honeypot"],"risk_details":[{"name":"honeypot","risk_desc":"the contract is honeypot","value":true}],"scanned_ts":1678701910}}
  '0xee84ba20dde325bd1e8a51e55b32f5f21cdb7a7a', //{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":0,"risk_type":["unverified_sourcecode","scam","scam"],"risk_details":[{"name":"unverified_sourcecode","risk_desc":"the contract has not verified sourcecode","value":true},{"name":"scam","risk_desc":"This address is scam","value":true},{"name":"abandoned","risk_desc":"This address is abandoned","value":true}],"scanned_ts":1678701893}}
  '0x4f2c61a611e1f28470fd7e5e0692052c94cf6a5d', //{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":0,"risk_type":["unverified_sourcecode","honeypot","scam"],"risk_details":[{"name":"unverified_sourcecode","risk_desc":"the contract has not verified sourcecode","value":true},{"name":"honeypot","risk_desc":"the contract is honeypot","value":true},{"name":"abandoned","risk_desc":"This address is abandoned","value":true}],"scanned_ts":1678701873}}
  '0xe1497a14a1224DaEFa5Fe68fD9e107Cb472e8129', //{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":40,"risk_type":["high_tax"],"risk_details":[{"name":"high_tax","risk_desc":"Buy or sell tax too high for this token","value":true}],"scanned_ts":1678701878}}
  '0xa7b5eabc3ee82c585f5f4ccc26b81c3bd62ff3a9', //{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":0,"risk_type":["honeypot","scam"],"risk_details":[{"name":"honeypot","risk_desc":"the contract is honeypot","value":true},{"name":"vulnerable","risk_desc":"This address is vulnerable","value":true}],"scanned_ts":1678701867}}
  '0x91eb90b084f6ee88031668c44ce21e225c000c34', //{"status":"OK","code":"000000000","data":{"has_result":true,"polling_interval":0,"address_type":"Contract","trust_score":0,"risk_type":["unverified_sourcecode","honeypot","scam","scam"],"risk_details":[{"name":"unverified_sourcecode","risk_desc":"the contract has not verified sourcecode","value":true},{"name":"honeypot","risk_desc":"the contract is honeypot","value":true},{"name":"scam","risk_desc":"This address is scam","value":true},{"name":"abandoned","risk_desc":"This address is abandoned","value":true}],"scanned_ts":1678701886}}
];

(async function main() {
  for (let address of ADDRESSES) {
    let result = await getRiskDetailForAddress(address);
    console.log("Risk score for: " + address);
    console.log(result);
    console.log ("--------------------------------------------------------");
  }
})();





