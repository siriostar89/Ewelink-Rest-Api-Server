import { createRequire } from "module";
let require = createRequire(import.meta.url);

const fs = require("fs");
const ewelink = require("ewelink-api");
const Zeroconf = require('ewelink-api/src/classes/Zeroconf');
const express = require("express");
const app = express();
const escape = require("escape-html");
const http = require("http");
const https = require("https");
const crypto = require("crypto");

// ------------------------------------------------------------------------------------------------------------------------
// Preperation
// ------------------------------------------------------------------------------------------------------------------------

try {
    fs.mkdirSync("./volume/ssl/");
} catch (e) {}

let ssl;
let useSsl;
let local = true;
try {
    ssl = {
        key: fs.readFileSync("./volume/ssl/privkey.pem", "utf8"),
        cert: fs.readFileSync("./volume/ssl/cert.pem", "utf8"),
    };
    useSsl = true;
} catch (e) {
    console.log(e);
    console.log("STarting server without encryption.");
    useSsl = false;
}

const devicesCache = await Zeroconf.loadCachedDevices();
const arpTable = await Zeroconf.loadArpTable();
const ewelinkConnection = new ewelink({ devicesCache, arpTable });
/*
if(fs.existsSync('device-cache.json') && fs.existsSync('arp-table.json')){
    const devicesCache = await Zeroconf.loadCachedDevices();
    const arpTable = await Zeroconf.loadArpTable();
    ewelinkConnection = new ewelink({ devicesCache, arpTable });
    console.log("Local mode activated!");
    local = true;
} else {
    ewelinkConnection = new ewelink({
        email: process.env.EWELINK_USERNAME,
        password: process.env.EWELINK_PASSWORD,
        region: process.env.EWELINK_REGION,
    });
}
*/

const constants = {
    port: parseInt(process.env.SERVER_PORT),
    defaultHashingAlgorithm: "sha3-512",
};

// disable console logging, if docker run -e "SERVER_MODE=prod"
if (process.env.SERVER_MODE == "prod") {
    console.log = () => {};
}

// (async function containerKeepAliveForAnalysis() {
//     console.log("Keeping container alive for filesystem analysis..");
//     while (true) {}
// })();

(async function initialize() {
    // test credentials
    if(local == false){
        let devices = await ewelinkConnection.getDevices();
        if ("error" in devices) console.log(devices.msg + ". The application will continue and respond with the error message, to make sure you are informed.");
    }

    // log hashed password on app start
    console.log("Supported hashing algorithms by crypto:");
    console.log(crypto.getHashes());
})();

app.use(express.json()); // treat all request bodies as application/json

// ------------------------------------------------------------------------------------------------------------------------
// Routing
// ------------------------------------------------------------------------------------------------------------------------

app.all("/", async (req, res, next) => {
    try {
        authenticate(req);
    } catch (e) {
        res.status(401).json(e);
        return;
    }

    next();
});

app.post("/", async (req, res) => {
    const requestedDeviceName = req.body.devicename != undefined ? String(req.body.devicename) : undefined;
    const requestedDeviceId = req.body.deviceid != undefined && req.body.deviceid != "" ? String(req.body.deviceid) : undefined;
    const requestedActionOnDevice = req.body.switch != undefined && req.body.switch != "" ? String(req.body.switch) : undefined;
    
    // const devices = await ewelinkConnection.getDevices();
    let textdata = fs.readFileSync('devices-cache.json');
    let devices = JSON.parse(textdata);
    devices = getDevicesData(devices);

    let selectedDevice;

    if (requestedDeviceId != undefined)
        // deviceid present?
        selectedDevice = requestedDeviceId;
    else {
        if (requestedDeviceName != undefined)
            // name keys present?
            selectedDevice = getDeviceByName(devices, requestedDeviceName);
        else {
            res.status(400).send(`You need to specify at least one of [deviceid, devicenameincludes]`);
            return;
        }
    }

    if (selectedDevice != undefined) {

        switch (requestedActionOnDevice) {
            case "on":
                await ewelinkConnection.setDevicePowerState(selectedDevice, 'on');
                res.status(200).send("ok");
                break;
            case "off":
                await ewelinkConnection.setDevicePowerState(selectedDevice, 'off');
                res.status(200).send("ok");
                break;
            default:
                res.status(400).send(`Invalid action ${escape(requestedActionOnDevice)}, valid choices are [on, off, toggle]`);
                break;
        }
    } else res.status(404).send(`No device found matching id: "${escape(requestedDeviceId)}" or name: "${escape(requestedDeviceName)}"`);
});

app.get("/", async (req, res) => {
    /*
    await ewelinkConnection.setDevicePowerState('1000c02b83', 'on');
    const devices = await ewelinkConnection.getDevices();
    */
    let textdata = fs.readFileSync('devices-cache.json');
    let devices = JSON.parse(textdata);
    devices = getDevicesData(devices);
    
    res.status(200).json(devices);
});

// ------------------------------------------------------------------------------------------------------------------------
// Server start
// ------------------------------------------------------------------------------------------------------------------------

if (useSsl) {
    https.createServer(ssl, app).listen(constants.port, () => {
        console.log(`Ewelink api server listening on https://localhost:${constants.port} (Container)`);
    });
} else {
    http.createServer(app).listen(constants.port, () => {
        console.log(`Ewelink api server listening on http://localhost:${constants.port} (Container)`);
    });
}

// ------------------------------------------------------------------------------------------------------------------------
// Functions
// ------------------------------------------------------------------------------------------------------------------------

/**
 * @param {Object[]} devices Contains all known devices
 * @param {String} name Contains a string to match the name fully
 * @returns {String} deviceID or null if not found
 */
function getDeviceByName(devices, name) {
    let deviceId = null;
    let dname = String(name).toLowerCase(); // device name to lowercase
    let rname; // array item device name
    devices.forEach(device => {
        rname = String(device[1]).toLowerCase();
        if(rname == dname || rname.indexOf(dname) !== -1){
            deviceId = device[0];
        }
    });
    return deviceId;
}

/**
 * @param {Object[]} devices Contains all known devices
 * @param {String[]} id ID of device to control, look up in ewelink app
 * @returns {Object} device, matching the given id
 */
function getDeviceById(devices, id) {
    let deviceToReturn = undefined;
    devices.forEach((device) => {
        if (String(device.deviceid) == id) deviceToReturn = device;
    });
    return deviceToReturn;
}

function authenticate(req) {
    if (useSsl) {
        if (req.headers.authorization == undefined) {
            throw "Authentication failed - bearer token missing";
        }

        const receivedToken = req.headers.authorization.replace("Bearer ", "");
        if (receivedToken != hashedPassword) throw "Authentication failed - wrong bearer token.";
    }
}

function hashPassword() {
    return crypto.createHash(hashingAlgorithm).update(process.env.EWELINK_PASSWORD).digest("hex");
}

function getDevicesData(jsonDevices){
    let id, name, mac;
    let devices = [], row = [];
    
    jsonDevices.forEach(element => {
        id = element['deviceid'];
        name = element['name'];
        mac = element['params']['staMac'];
        if(mac !== undefined){
            row = [id, name, mac];
            devices.push(row);
        }
    });
    return devices;
}