
var rijndael = {
  keySizeInBits: 128,
  blockSizeInBits: 128,
  roundsArray: [, , , , [, , , , 10, , 12, , 14], , [, , , , 12, , 12, , 14], , [, , , , 14, , 14, , 14]],
  shiftOffsets: [, , , , [, 1, 2, 3], , [, 1, 2, 3], , [, 1, 3, 4]],
  Rcon: [1, 2, 4, 8, 16, 32, 64, 128, 27, 54, 108, 216, 171, 77, 154, 47, 94, 188, 99, 198, 151, 53, 106, 212, 179, 125, 250, 239, 197, 145],
  SBox: [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22],
  SBoxInverse: [82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125],
  cyclicShiftLeft: function(c, a) {
      var b = c.slice(0, a);
      c = c.slice(a).concat(b);
      return c
  },
  xtime: function(a) {
      a <<= 1;
      return ((a & 256) ? (a ^ 283) : (a))
  },
  mult_GF256: function(b, d) {
      var c, a = 0;
      for (c = 1; c < 256; c *= 2,
      d = this.xtime(d)) {
          if (b & c) {
              a ^= d
          }
      }
      return a
  },
  byteSub: function(d, e) {
      var c;
      if (e == "encrypt") {
          c = this.SBox
      } else {
          c = this.SBoxInverse
      }
      for (var b = 0; b < 4; b++) {
          for (var a = 0; a < this.Nb; a++) {
              d[b][a] = c[d[b][a]]
          }
      }
  },
  shiftRow: function(b, c) {
      for (var a = 1; a < 4; a++) {
          if (c == "encrypt") {
              b[a] = this.cyclicShiftLeft(b[a], this.shiftOffsets[this.Nb][a])
          } else {
              b[a] = this.cyclicShiftLeft(b[a], this.Nb - this.shiftOffsets[this.Nb][a])
          }
      }
  },
  mixColumn: function(e, f) {
      var a = [];
      for (var c = 0; c < this.Nb; c++) {
          for (var d = 0; d < 4; d++) {
              if (f == "encrypt") {
                  a[d] = this.mult_GF256(e[d][c], 2) ^ this.mult_GF256(e[(d + 1) % 4][c], 3) ^ e[(d + 2) % 4][c] ^ e[(d + 3) % 4][c]
              } else {
                  a[d] = this.mult_GF256(e[d][c], 14) ^ this.mult_GF256(e[(d + 1) % 4][c], 11) ^ this.mult_GF256(e[(d + 2) % 4][c], 13) ^ this.mult_GF256(e[(d + 3) % 4][c], 9)
              }
          }
          for (var d = 0; d < 4; d++) {
              e[d][c] = a[d]
          }
      }
  },
  addRoundKey: function(b, c) {
      for (var a = 0; a < this.Nb; a++) {
          b[0][a] ^= (c[a] & 255);
          b[1][a] ^= ((c[a] >> 8) & 255);
          b[2][a] ^= ((c[a] >> 16) & 255);
          b[3][a] ^= ((c[a] >> 24) & 255)
      }
  },
  keyExpansion: function(d) {
      var c = [];
      var a;
      this.Nk = this.keySizeInBits / 32;
      this.Nb = this.blockSizeInBits / 32;
      this.Nr = this.roundsArray[this.Nk][this.Nb];
      for (var b = 0; b < this.Nk; b++) {
          c[b] = (d[4 * b]) | (d[4 * b + 1] << 8) | (d[4 * b + 2] << 16) | (d[4 * b + 3] << 24)
      }
      for (b = this.Nk; b < this.Nb * (this.Nr + 1); b++) {
          a = c[b - 1];
          if (b % this.Nk == 0) {
              a = ((this.SBox[(a >> 8) & 255]) | (this.SBox[(a >> 16) & 255] << 8) | (this.SBox[(a >> 24) & 255] << 16) | (this.SBox[a & 255] << 24)) ^ this.Rcon[Math.floor(b / this.Nk) - 1]
          } else {
              if (this.Nk > 6 && b % this.Nk == 4) {
                  a = (this.SBox[(a >> 24) & 255] << 24) | (this.SBox[(a >> 16) & 255] << 16) | (this.SBox[(a >> 8) & 255] << 8) | (this.SBox[a & 255])
              }
          }
          c[b] = c[b - this.Nk] ^ a
      }
      return c
  },
  Round: function(a, b) {
      this.byteSub(a, "encrypt");
      this.shiftRow(a, "encrypt");
      this.mixColumn(a, "encrypt");
      this.addRoundKey(a, b)
  },
  InverseRound: function(a, b) {
      this.addRoundKey(a, b);
      this.mixColumn(a, "decrypt");
      this.shiftRow(a, "decrypt");
      this.byteSub(a, "decrypt")
  },
  FinalRound: function(a, b) {
      this.byteSub(a, "encrypt");
      this.shiftRow(a, "encrypt");
      this.addRoundKey(a, b)
  },
  InverseFinalRound: function(a, b) {
      this.addRoundKey(a, b);
      this.shiftRow(a, "decrypt");
      this.byteSub(a, "decrypt")
  },
  encrypt: function(c, a) {
      var b;
      if (!c || c.length * 8 != this.blockSizeInBits) {
          return
      }
      if (!a) {
          return
      }
      c = this.packBytes(c);
      this.addRoundKey(c, a);
      for (b = 1; b < this.Nr; b++) {
          this.Round(c, a.slice(this.Nb * b, this.Nb * (b + 1)))
      }
      this.FinalRound(c, a.slice(this.Nb * this.Nr));
      return this.unpackBytes(c)
  },
  decrypt: function(c, a) {
      var b;
      if (!c || c.length * 8 != this.blockSizeInBits) {
          return
      }
      if (!a) {
          return
      }
      c = this.packBytes(c);
      this.InverseFinalRound(c, a.slice(this.Nb * this.Nr));
      for (b = this.Nr - 1; b > 0; b--) {
          this.InverseRound(c, a.slice(this.Nb * b, this.Nb * (b + 1)))
      }
      this.addRoundKey(c, a);
      return this.unpackBytes(c)
  },
  byteArrayToString: function(c) {
      var b = "";
      var a = c.length;
      for (var d = 0; d < a; d++) {
          if (c[d] != 0) {
              b += String.fromCharCode(c[d])
          }
      }
      return b
  },
  stringToByteArray: function(c) {
      var b = [];
      var a = c.length;
      for (var d = 0; d < a; d++) {
          b[b.length] = c.charCodeAt()
      }
      return b
  },
  byteArrayToHex: function(c) {
      var b = "";
      if (!c) {
          return
      }
      var a = c.length;
      for (var d = 0; d < a; d++) {
          b += ((c[d] < 16) ? "0" : "") + c[d].toString(16)
      }
      return b
  },
  hexToByteArray: function(c) {
      var b = [];
      if (c.length % 2) {
          return
      }
      if (c.indexOf("0x") == 0 || c.indexOf("0X") == 0) {
          c = c.substring(2)
      }
      var a = c.length;
      for (var d = 0; d < a; d += 2) {
          b[Math.floor(d / 2)] = parseInt(c.slice(d, d + 2), 16)
      }
      return b
  },
  packBytes: function(c) {
      var d = [];
      if (!c || c.length % 4) {
          return
      }
      d[0] = [];
      d[1] = [];
      d[2] = [];
      d[3] = [];
      var a = c.length;
      for (var b = 0; b < a; b += 4) {
          d[0][b / 4] = c[b];
          d[1][b / 4] = c[b + 1];
          d[2][b / 4] = c[b + 2];
          d[3][b / 4] = c[b + 3]
      }
      return d
  },
  unpackBytes: function(c) {
      var b = [];
      var a = c[0].length;
      for (var d = 0; d < a; d++) {
          b[b.length] = c[0][d];
          b[b.length] = c[1][d];
          b[b.length] = c[2][d];
          b[b.length] = c[3][d]
      }
      return b
  },
  formatPlaintext: function(c) {
      var d = this.blockSizeInBits / 8;
      var b;
      if (typeof c == "string" || c.indexOf) {
          c = c.split("");
          var a = c.length;
          for (b = 0; b < a; b++) {
              c[b] = c[b].charCodeAt(0) & 255
          }
      }
      for (b = d - (c.length % d); b > 0 && b < d; b--) {
          c[c.length] = 0
      }
      return c
  },
  getRandomBytes: function(c) {
      var b;
      var a = [];
      for (b = 0; b < c; b++) {
          a[b] = Math.round(Math.random() * 255)
      }
      return a
  },
  rijndaelEncrypt: function(b, h, f) {
      var c, e, k;
      var a = this.blockSizeInBits / 8;
      var g;
      if (!b || !h) {
          return
      }
      if (h.length * 8 != this.keySizeInBits) {
          return
      }
      if (f == "CBC") {
          g = this.getRandomBytes(a)
      } else {
          f = "ECB";
          g = []
      }
      b = this.formatPlaintext(b);
      c = this.keyExpansion(h);
      for (var d = 0; d < b.length / a; d++) {
          k = b.slice(d * a, (d + 1) * a);
          if (f == "CBC") {
              for (var e = 0; e < a; e++) {
                  k[e] ^= g[d * a + e]
              }
          }
          g = g.concat(this.encrypt(k, c))
      }
      return g
  },
  rijndaelDecrypt: function(c, g, f) {
      var b;
      var a = this.blockSizeInBits / 8;
      var k = [];
      var h;
      var d;
      if (!c || !g || typeof c == "string") {
          return
      }
      if (g.length * 8 != this.keySizeInBits) {
          return
      }
      if (!f) {
          f = "ECB"
      }
      b = this.keyExpansion(g);
      for (d = (c.length / a) - 1; d > 0; d--) {
          h = this.decrypt(c.slice(d * a, (d + 1) * a), b);
          if (f == "CBC") {
              for (var e = 0; e < a; e++) {
                  k[(d - 1) * a + e] = h[e] ^ c[(d - 1) * a + e]
              }
          } else {
              k = h.concat(k)
          }
      }
      if (f == "ECB") {
          k = this.decrypt(c.slice(0, a), b).concat(k)
      }
      return k
  },
  _init: function() {
      this.Nk = this.keySizeInBits / 32;
      this.Nb = this.blockSizeInBits / 32;
      this.Nr = this.roundsArray[this.Nk][this.Nb]
  }
};
function MainEncrtpt(b, a) {
      try {
          a = (a == null) ? this.key : a;
          if (a != null) {
              var g = rijndael;
              a = g.hexToByteArray(a);
              var c = g.rijndaelEncrypt(b, a);
              var f = g.byteArrayToHex(c);
              return f
          }
      } catch (d) {
          //gx.dbg.logEx(d, "gxfrmutl.js", "encrypt")
      }
      return b
  }

const http = require('http');

const hostname = '127.0.0.1';
const port = 3000;

const server = http.createServer((req, res) => {
  var query = require('url').parse(req.url,true).query;
  var codificacao = MainEncrtpt("gxajaxEvt",query.key);
  res.statusCode = 200;
  res.setHeader('Content-Type', 'text/plain');
  res.end(codificacao);
});

server.listen(port, hostname, () => {
  console.log(`Server running at http://${hostname}:${port}/`);
});
