//REGEX for common secrets
var secrets = ["BEGIN DSA PRIVATE KEY",
"BEGIN EC PRIVATE KEY",
"BEGIN OPENSSH PRIVATE KEY",
"BEGIN PGP PRIVATE KEY BLOCK",
"BEGIN PRIVATE KEY",
"BEGIN RSA PRIVATE KEY",
"BEGIN SSH2 ENCRYPTED PRIVATE KEY",
"PuTTY-User-Key-File-2",
"password",
"MSSQL",
"MySQL",
"MariaDB",
"database",
"root",
"administrator",
"secret",
"^(?!666|000|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0{4})\\d{4}$",
"(?<=:\/\/)[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+",
"bearer [a-zA-Z0-9_\\-\\.=]+",
"basic [a-zA-Z0-9_\\-:\\.=]+",
"\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b"];


var element = document.getElementById("__VIEWSTATE");
var encryptedFlag = document.getElementById("__VIEWSTATEENCRYPTED");
var generator = document.getElementById("__VIEWSTATEGENERATOR")

class SimulateDotnet45KdfContextParameters {
  constructor(url) {
      this.url = url;
  }

  simulateTemplateSourceDirectory(strPath) {
      strPath = strPath.startsWith("/") ? strPath : "/" + strPath;
      const pathParts = strPath.split("/");
      strPath = pathParts[pathParts.length - 1].includes(".") ? strPath : pathParts.slice(0, -1).join("/");
      strPath = this.removeSlashFromPathIfNeeded(strPath);
      return strPath || "/";
  }

  static removeSlashFromPathIfNeeded(path) {
      return path && path.endsWith("/") ? path.slice(0, -1) : path;
  }

  simulateGetTypeName(strPath, iisAppInPath) {
      strPath = strPath.startsWith("/") ? strPath : "/" + strPath;
      iisAppInPath = iisAppInPath.toLowerCase().startsWith("/") ? iisAppInPath.toLowerCase() : "/" + iisAppInPath.toLowerCase();
      strPath = strPath.toLowerCase().endsWith(".aspx") ? strPath : strPath + "/default.aspx";
      iisAppInPath = iisAppInPath.endsWith("/") ? iisAppInPath : iisAppInPath + "/";
      strPath = strPath.toLowerCase().includes(iisAppInPath.toLowerCase()) ? strPath.split(iisAppInPath.toLowerCase())[1] : strPath;
      strPath = strPath.startsWith("/") ? strPath.slice(1) : strPath;
      strPath = strPath.replace(/\./g, "_").replace(/\//g, "_");
      strPath = this.removeSlashFromPathIfNeeded(strPath);
      return strPath;
  }

  static extractFromUrl(url) {
      const parsedUrl = new URL(url);
      const strPath = parsedUrl.pathname;
      const iisAppInPath = strPath.split("/").slice(0, -1).join("/") || "/";
      return [strPath, iisAppInPath];
  }

  getSpecificPurposes() {
      const [strPath, iisAppInPath] = SimulateDotnet45KdfContextParameters.extractFromUrl(this.url);
      const templateSource = this.simulateTemplateSourceDirectory(iisAppInPath);
      const getType = this.simulateGetTypeName(strPath, iisAppInPath);
      const specificPurposes = [
          `TemplateSourceDirectory: ${templateSource.toUpperCase()}`,
          `Type: ${getType.toUpperCase()}`
      ];
      return specificPurposes;
  }
}

function sp800_108_get_key_derivation_parameters(primaryPurpose, specificPurposes) {
  const derivedKeyLabel = new TextEncoder().encode(primaryPurpose);
  const derivedKeyContext = new Uint8Array(specificPurposes.map(purpose => writeVlqString(purpose)).flat());
  return [derivedKeyLabel, derivedKeyContext];
}

function writeVlqString(str) {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(str);
  const vlqLength = encodeVlq(bytes.length);
  return new Uint8Array([...vlqLength, ...bytes]);
}

function encodeVlq(value) {
  const result = [];
  while (true) {
      let byte = value & 0x7F;
      value >>>= 7;
      if (value === 0) {
          result.push(byte);
          break;
      } else {
          byte |= 0x80;
          result.push(byte);
      }
  }
  return result;
}

function sp800_108_derivekey(key, label, context, keyLengthInBits) {
    const lblcnt = label ? label.length : 0;
    const ctxcnt = context ? context.length : 0;
    let buffer = Buffer.alloc(4 + lblcnt + 1 + ctxcnt + 4);

    if (lblcnt !== 0) {
        buffer = Buffer.concat([buffer.slice(0, 4), Buffer.from(label), buffer.slice(4 + lblcnt)]);
    }

    if (ctxcnt !== 0) {
        buffer = Buffer.concat([buffer.slice(0, 5 + lblcnt), Buffer.from(context), buffer.slice(5 + lblcnt + ctxcnt)]);
    }

    buffer = Buffer.concat([buffer.slice(0, 5 + lblcnt + ctxcnt), _writeUint(keyLengthInBits), buffer.slice(5 + lblcnt + ctxcnt + 4)]);

    let v = Math.floor(keyLengthInBits / 8);
    let res = Buffer.alloc(v);
    let num = 1;

    while (v > 0) {
        buffer = Buffer.concat([_writeUint(num), buffer.slice(4)]);
        const h = crypto.createHmac('sha512', key);
        const hash = h.update(buffer).digest();
        const cnt = Math.min(v, hash.length);
        res = Buffer.concat([hash.slice(0, cnt), res.slice(cnt)]);
        v -= cnt;
        num += 1;
    }

    return res;
}

function _writeUint(value) {
    const buffer = Buffer.alloc(4);
    buffer.writeUInt32BE(value, 0);
    return buffer;
}
//Since JS crypto subtle doesnt support MD5 ?!?!?, we have to use MD5 from here: https://www.myersdaily.org/joseph/javascript/md5-text.html
function md5cycle(x, k) {
  var a = x[0], b = x[1], c = x[2], d = x[3];
  
  a = ff(a, b, c, d, k[0], 7, -680876936);
  d = ff(d, a, b, c, k[1], 12, -389564586);
  c = ff(c, d, a, b, k[2], 17,  606105819);
  b = ff(b, c, d, a, k[3], 22, -1044525330);
  a = ff(a, b, c, d, k[4], 7, -176418897);
  d = ff(d, a, b, c, k[5], 12,  1200080426);
  c = ff(c, d, a, b, k[6], 17, -1473231341);
  b = ff(b, c, d, a, k[7], 22, -45705983);
  a = ff(a, b, c, d, k[8], 7,  1770035416);
  d = ff(d, a, b, c, k[9], 12, -1958414417);
  c = ff(c, d, a, b, k[10], 17, -42063);
  b = ff(b, c, d, a, k[11], 22, -1990404162);
  a = ff(a, b, c, d, k[12], 7,  1804603682);
  d = ff(d, a, b, c, k[13], 12, -40341101);
  c = ff(c, d, a, b, k[14], 17, -1502002290);
  b = ff(b, c, d, a, k[15], 22,  1236535329);
  
  a = gg(a, b, c, d, k[1], 5, -165796510);
  d = gg(d, a, b, c, k[6], 9, -1069501632);
  c = gg(c, d, a, b, k[11], 14,  643717713);
  b = gg(b, c, d, a, k[0], 20, -373897302);
  a = gg(a, b, c, d, k[5], 5, -701558691);
  d = gg(d, a, b, c, k[10], 9,  38016083);
  c = gg(c, d, a, b, k[15], 14, -660478335);
  b = gg(b, c, d, a, k[4], 20, -405537848);
  a = gg(a, b, c, d, k[9], 5,  568446438);
  d = gg(d, a, b, c, k[14], 9, -1019803690);
  c = gg(c, d, a, b, k[3], 14, -187363961);
  b = gg(b, c, d, a, k[8], 20,  1163531501);
  a = gg(a, b, c, d, k[13], 5, -1444681467);
  d = gg(d, a, b, c, k[2], 9, -51403784);
  c = gg(c, d, a, b, k[7], 14,  1735328473);
  b = gg(b, c, d, a, k[12], 20, -1926607734);
  
  a = hh(a, b, c, d, k[5], 4, -378558);
  d = hh(d, a, b, c, k[8], 11, -2022574463);
  c = hh(c, d, a, b, k[11], 16,  1839030562);
  b = hh(b, c, d, a, k[14], 23, -35309556);
  a = hh(a, b, c, d, k[1], 4, -1530992060);
  d = hh(d, a, b, c, k[4], 11,  1272893353);
  c = hh(c, d, a, b, k[7], 16, -155497632);
  b = hh(b, c, d, a, k[10], 23, -1094730640);
  a = hh(a, b, c, d, k[13], 4,  681279174);
  d = hh(d, a, b, c, k[0], 11, -358537222);
  c = hh(c, d, a, b, k[3], 16, -722521979);
  b = hh(b, c, d, a, k[6], 23,  76029189);
  a = hh(a, b, c, d, k[9], 4, -640364487);
  d = hh(d, a, b, c, k[12], 11, -421815835);
  c = hh(c, d, a, b, k[15], 16,  530742520);
  b = hh(b, c, d, a, k[2], 23, -995338651);
  
  a = ii(a, b, c, d, k[0], 6, -198630844);
  d = ii(d, a, b, c, k[7], 10,  1126891415);
  c = ii(c, d, a, b, k[14], 15, -1416354905);
  b = ii(b, c, d, a, k[5], 21, -57434055);
  a = ii(a, b, c, d, k[12], 6,  1700485571);
  d = ii(d, a, b, c, k[3], 10, -1894986606);
  c = ii(c, d, a, b, k[10], 15, -1051523);
  b = ii(b, c, d, a, k[1], 21, -2054922799);
  a = ii(a, b, c, d, k[8], 6,  1873313359);
  d = ii(d, a, b, c, k[15], 10, -30611744);
  c = ii(c, d, a, b, k[6], 15, -1560198380);
  b = ii(b, c, d, a, k[13], 21,  1309151649);
  a = ii(a, b, c, d, k[4], 6, -145523070);
  d = ii(d, a, b, c, k[11], 10, -1120210379);
  c = ii(c, d, a, b, k[2], 15,  718787259);
  b = ii(b, c, d, a, k[9], 21, -343485551);
  
  x[0] = add32(a, x[0]);
  x[1] = add32(b, x[1]);
  x[2] = add32(c, x[2]);
  x[3] = add32(d, x[3]);
  
  }
  
  function cmn(q, a, b, x, s, t) {
  a = add32(add32(a, q), add32(x, t));
  return add32((a << s) | (a >>> (32 - s)), b);
  }
  
  function ff(a, b, c, d, x, s, t) {
  return cmn((b & c) | ((~b) & d), a, b, x, s, t);
  }
  
  function gg(a, b, c, d, x, s, t) {
  return cmn((b & d) | (c & (~d)), a, b, x, s, t);
  }
  
  function hh(a, b, c, d, x, s, t) {
  return cmn(b ^ c ^ d, a, b, x, s, t);
  }
  
  function ii(a, b, c, d, x, s, t) {
  return cmn(c ^ (b | (~d)), a, b, x, s, t);
  }
  
  function md51(s) {
  txt = '';
  var n = s.length,
  state = [1732584193, -271733879, -1732584194, 271733878], i;
  for (i=64; i<=s.length; i+=64) {
  md5cycle(state, md5blk(s.substring(i-64, i)));
  }
  s = s.substring(i-64);
  var tail = [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0];
  for (i=0; i<s.length; i++)
  tail[i>>2] |= s.charCodeAt(i) << ((i%4) << 3);
  tail[i>>2] |= 0x80 << ((i%4) << 3);
  if (i > 55) {
  md5cycle(state, tail);
  for (i=0; i<16; i++) tail[i] = 0;
  }
  tail[14] = n*8;
  md5cycle(state, tail);
  return state;
  }
  
  /* there needs to be support for Unicode here,
   * unless we pretend that we can redefine the MD-5
   * algorithm for multi-byte characters (perhaps
   * by adding every four 16-bit characters and
   * shortening the sum to 32 bits). Otherwise
   * I suggest performing MD-5 as if every character
   * was two bytes--e.g., 0040 0025 = @%--but then
   * how will an ordinary MD-5 sum be matched?
   * There is no way to standardize text to something
   * like UTF-8 before transformation; speed cost is
   * utterly prohibitive. The JavaScript standard
   * itself needs to look at this: it should start
   * providing access to strings as preformed UTF-8
   * 8-bit unsigned value arrays.
   */
  function md5blk(s) { /* I figured global was faster.   */
  var md5blks = [], i; /* Andy King said do it this way. */
  for (i=0; i<64; i+=4) {
  md5blks[i>>2] = s.charCodeAt(i)
  + (s.charCodeAt(i+1) << 8)
  + (s.charCodeAt(i+2) << 16)
  + (s.charCodeAt(i+3) << 24);
  }
  return md5blks;
  }
  
  var hex_chr = '0123456789abcdef'.split('');
  
  function rhex(n)
  {
  var s='', j=0;
  for(; j<4; j++)
  s += hex_chr[(n >> (j * 8 + 4)) & 0x0F]
  + hex_chr[(n >> (j * 8)) & 0x0F];
  return s;
  }
  
  function hex(x) {
  for (var i=0; i<x.length; i++)
  x[i] = rhex(x[i]);
  return x.join('');
  }
  
  function md5(s) {
  return hex(md51(s));
  }
  
  /* this function is much faster,
  so if possible we use it. Some IEs
  are the only ones I know of that
  need the idiotic second function,
  generated by an if clause.  */
  
  function add32(a, b) {
  return (a + b) & 0xFFFFFFFF;
  }
  
  if (md5('hello') != '5d41402abc4b2a76b9719d911017c592') {
  function add32(x, y) {
  var lsw = (x & 0xFFFF) + (y & 0xFFFF),
  msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
  }
  }

function hexToString(hex) {
    let str = '';
    for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    }
    return str;
}

function hexToUint8Array(hex) {
  return Uint8Array.from(hex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16)));
}

function testMD5(viewstate, key) {
    //Takes the viewstate data appends the key, and then hashes with MD5. Returns just the MD5 hash.
    // Decode base64 to bytes
    //const decodedBase64 = atob(viewstate)
    //Convert the hex bytes to a string and append the needed 4 empty bytes for non-encrypted viewstates

    var hexKey = hexToString(key);

    const hexBytes = hexKey += "\x00\x00\x00\x00"

    // Append hexInput to decodedBase64
    const concatenatedHex = viewstate + hexBytes;

    // Hash the concatenatedString using MD5
    const md5Hash = md5(concatenatedHex);

    return md5Hash;
}


async function calculateHMAC(base64Data, hexAdditionalData, hexKey, algo) {

  if (hexKey == null){

    return "Invalid key"
  }
  // Convert Base64 data to Uint8Array
  const dataBuffer = new Uint8Array(base64Data.split('').map(char => char.charCodeAt(0)));

  // Convert hex additional data and key to Uint8Array
  const additionalDataBuffer = new Uint8Array(hexToBytes(hexAdditionalData)).reverse();
  const keyBuffer = new Uint8Array(hexToBytes(hexKey));

  
  // Import the key
  const importedKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: { name: algo } },
    false,
    ['sign']
  );

  // Concatenate data and additional data
  const concatenatedBuffer = new Uint8Array(dataBuffer.length + additionalDataBuffer.length);
  concatenatedBuffer.set(dataBuffer);
  concatenatedBuffer.set(additionalDataBuffer, dataBuffer.length);

  // Calculate HMAC
  const hmacBuffer = await crypto.subtle.sign(
    { name: 'HMAC', hash: { name: algo } },
    importedKey,
    concatenatedBuffer
  );

  // Convert the result to hex
  const hmacHex = bytesToHex(new Uint8Array(hmacBuffer));

  return hmacHex;
}

// Helper function to convert hex string to Uint8Array
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Helper function to convert Uint8Array to hex string
function bytesToHex(bytes) {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}



// Listen for messages
chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
    // If the received message has the expected format...
    if (msg.text === 'get_viewstate') {
        // Call the specified callback, passing
        // the web-page's DOM content as argument
        element = document.getElementById("__VIEWSTATE");
        generator = document.getElementById("__VIEWSTATEGENERATOR")
        if (element != null){
          sendResponse(element.value, generator);
        } else {
          sendResponse("NOT FOUND", null);
        }
    }
});


if(element != null){
  //alert("Viewstate on page!");
  var siteBody = document.getElementsByTagName('body')[0];
  var addedElement = document.createElement('div');
  var exitBtn =  document.createElement('button');
  exitBtn.setAttribute("style", "all: unset; position: fixed;right: 4px; width: 15px;background-color: darkgray;font-size: small;top: 3px;");
  exitBtn.setAttribute("onclick", "document.body.removeChild(this.parentNode)");
  exitBtn.innerHTML = "X";
  addedElement.appendChild(document.createTextNode('VIEWSTATE'));
  addedElement.appendChild(exitBtn);
  addedElement.setAttribute("style", "position: fixed !important;top: 0px !important;z-index: 2147483647 !important;width:  100%;background-color: red !important;text-align: center;font-size: large;font-weight: bold;")
  siteBody.insertBefore(addedElement, siteBody.firstChild);
  //console.log(siteBody);

  //Search for common secrets using regex
  var viewstateRAW = atob(element.value);
  for (s in secrets) {
    var re = new RegExp(secrets[s]);
    var regexTest = re.test(viewstateRAW);
    if(regexTest == true){
      alert("Found secret in Viewstate!");
      console.log("Found secret in viewstate matching: " + secrets[s]);
    }
  }

  //process viewstate against known keys
  //From/based on: https://stackoverflow.com/questions/66723640/how-to-get-another-file-content-from-content-script-in-chrome-extension
  //const url = chrome.runtime.getURL('valkeys.txt');
  //async function loadKeyfile() {
  //  var text = await fetch(url).then((responce) => {
  //      if (responce.ok) {
  //          //console.log(responce.text())
  //          return responce.text()// or responce.json() to json-style object
//
   //     } else { throw "Error: File was not found or can't be reached" }
  //  })
  //}
  //const rawKeyFile = loadKeyfile().then()

  //const keyfile = rawKeyFile.split("\n");

  async function loadAndSplitFileByLine(filename) {
    // Get the URL of the file within the extension
    const fileURL = chrome.runtime.getURL(filename);
  
    try {
      // Fetch the content of the file
      const response = await fetch(fileURL);
  
      if (!response.ok) {
        throw new Error(`Failed to fetch ${filename}`);
      }
  
      // Read the content as text
      const fileContent = await response.text();
  
      // Split the content by lines
      const lines = fileContent.split('\n');
  
      // Remove empty lines
      const nonEmptyLines = lines.filter(line => line.trim() !== '');
  
      return nonEmptyLines;
    } catch (error) {
      console.error(error.message);
      return null;
    }
  }
  const filename = 'valkeys.txt';
  keyfile = loadAndSplitFileByLine(filename)
  .then(lines => {
    if (lines) {
        //MD5 length cut
        keyfile = lines;
          var justViewstate = viewstateRAW.slice(0, viewstateRAW.length - 16);
          var signatureVal = viewstateRAW.slice(viewstateRAW.length - 15, viewstateRAW.length);
          //console.log(keyfile);
          for (key in keyfile) {
            //console.log(key);
            //console.log(testMD5(justViewstate, key));
            if(testMD5(justViewstate, key) == signatureVal) {
              alert("USING KNOWN KEY FOR VIEWSTATE!!!!!!")
            }
          }
          console.log("Done with MD5")
          //SHA1
          var justViewstate = viewstateRAW.slice(0, viewstateRAW.length - 20);
          var signatureVal = viewstateRAW.slice(viewstateRAW.length - 19, viewstateRAW.length);
          for (key in keyfile) {
            if(calculateHMAC(justViewstate, generator.value, key, "SHA-1") == signatureVal) {
              alert("USING KNOWN KEY FOR VIEWSTATE!!!!!!")
            }
          }
          console.log("Done with SHA1")
          //SHA256
          var justViewstate = viewstateRAW.slice(0, viewstateRAW.length - 32);
          var signatureVal = viewstateRAW.slice(viewstateRAW.length - 31, viewstateRAW.length);
          for (key in keyfile) {
            if(calculateHMAC(justViewstate, generator.value, key, "SHA-256") == signatureVal) {
              alert("USING KNOWN KEY FOR VIEWSTATE!!!!!!")
            }
          }
          console.log("Done with SHA256")
          //SHA384
          var justViewstate = viewstateRAW.slice(0, viewstateRAW.length - 48);
          var signatureVal = viewstateRAW.slice(viewstateRAW.length - 47, viewstateRAW.length);
          for (key in keyfile) {
            if(calculateHMAC(justViewstate, generator.value, key, "SHA-384") == signatureVal) {
              alert("USING KNOWN KEY FOR VIEWSTATE!!!!!!")
            }
          }
          console.log("Done with SHA384")
          //SHA512
          var justViewstate = viewstateRAW.slice(0, viewstateRAW.length - 64);
          var signatureVal = viewstateRAW.slice(viewstateRAW.length - 63, viewstateRAW.length);
          for (key in keyfile) {
            if(calculateHMAC(justViewstate, generator.value, key, "SHA-512") == signatureVal) {
              alert("USING KNOWN KEY FOR VIEWSTATE!!!!!!")
            }
          }
          console.log("Done with SHA512")
            } else {
              console.log('Failed to load and split the file.');
            }
  });


  
  if(encryptedFlag == null){
    //TODO: Add decryption/common keys?
    //TODO: Add support to change DIV notification to show encrypted viewstate
    //alert("Encrypted Viewstate!");


  }


}
