function IllegalStateError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
IllegalStateError.prototype = Object.create( Error.prototype, { name: { value: 'IllegalStateError' } } );

function IllegalArgumentError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
IllegalArgumentError.prototype = Object.create( Error.prototype, { name: { value: 'IllegalArgumentError' } } );

function SecurityError () { var err = Error.apply( this, arguments ); this.message = err.message, this.stack = err.stack; }
SecurityError.prototype = Object.create( Error.prototype, { name: { value: 'SecurityError' } } );
var FloatArray = global.Float64Array || global.Float32Array; // make PhantomJS happy

function string_to_bytes ( str, utf8 ) {
    utf8 = !!utf8;

    var len = str.length,
        bytes = new Uint8Array( utf8 ? 4*len : len );

    for ( var i = 0, j = 0; i < len; i++ ) {
        var c = str.charCodeAt(i);

        if ( utf8 && 0xd800 <= c && c <= 0xdbff ) {
            if ( ++i >= len ) throw new Error( "Malformed string, low surrogate expected at position " + i );
            c = ( (c ^ 0xd800) << 10 ) | 0x10000 | ( str.charCodeAt(i) ^ 0xdc00 );
        }
        else if ( !utf8 && c >>> 8 ) {
            throw new Error("Wide characters are not allowed.");
        }

        if ( !utf8 || c <= 0x7f ) {
            bytes[j++] = c;
        }
        else if ( c <= 0x7ff ) {
            bytes[j++] = 0xc0 | (c >> 6);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
        else if ( c <= 0xffff ) {
            bytes[j++] = 0xe0 | (c >> 12);
            bytes[j++] = 0x80 | (c >> 6 & 0x3f);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
        else {
            bytes[j++] = 0xf0 | (c >> 18);
            bytes[j++] = 0x80 | (c >> 12 & 0x3f);
            bytes[j++] = 0x80 | (c >> 6 & 0x3f);
            bytes[j++] = 0x80 | (c & 0x3f);
        }
    }

    return bytes.subarray(0, j);
}

function hex_to_bytes ( str ) {
    var len = str.length;
    if ( len & 1 ) {
        str = '0'+str;
        len++;
    }
    var bytes = new Uint8Array(len>>1);
    for ( var i = 0; i < len; i += 2 ) {
        bytes[i>>1] = parseInt( str.substr( i, 2), 16 );
    }
    return bytes;
}

function base64_to_bytes ( str ) {
    return string_to_bytes( atob( str ) );
}

function bytes_to_string ( bytes, utf8 ) {
    utf8 = !!utf8;

    var len = bytes.length,
        chars = new Array(len);

    for ( var i = 0, j = 0; i < len; i++ ) {
        var b = bytes[i];
        if ( !utf8 || b < 128 ) {
            chars[j++] = b;
        }
        else if ( b >= 192 && b < 224 && i+1 < len ) {
            chars[j++] = ( (b & 0x1f) << 6 ) | (bytes[++i] & 0x3f);
        }
        else if ( b >= 224 && b < 240 && i+2 < len ) {
            chars[j++] = ( (b & 0xf) << 12 ) | ( (bytes[++i] & 0x3f) << 6 ) | (bytes[++i] & 0x3f);
        }
        else if ( b >= 240 && b < 248 && i+3 < len ) {
            var c = ( (b & 7) << 18 ) | ( (bytes[++i] & 0x3f) << 12 ) | ( (bytes[++i] & 0x3f) << 6 ) | (bytes[++i] & 0x3f);
            if ( c <= 0xffff ) {
                chars[j++] = c;
            }
            else {
                c ^= 0x10000;
                chars[j++] = 0xd800 | (c >> 10);
                chars[j++] = 0xdc00 | (c & 0x3ff);
            }
        }
        else {
            throw new Error("Malformed UTF8 character at byte offset " + i);
        }
    }

    var str = '',
        bs = 16384;
    for ( var i = 0; i < j; i += bs ) {
        str += String.fromCharCode.apply( String, chars.slice( i, i+bs <= j ? i+bs : j ) );
    }

    return str;
}

function bytes_to_hex ( arr ) {
    var str = '';
    for ( var i = 0; i < arr.length; i++ ) {
        var h = ( arr[i] & 0xff ).toString(16);
        if ( h.length < 2 ) str += '0';
        str += h;
    }
    return str;
}

function bytes_to_base64 ( arr ) {
    return btoa( bytes_to_string(arr) );
}

function pow2_ceil ( a ) {
    a -= 1;
    a |= a >>> 1;
    a |= a >>> 2;
    a |= a >>> 4;
    a |= a >>> 8;
    a |= a >>> 16;
    a += 1;
    return a;
}

function is_number ( a ) {
    return ( typeof a === 'number' );
}

function is_string ( a ) {
    return ( typeof a === 'string' );
}

function is_buffer ( a ) {
    return ( a instanceof ArrayBuffer );
}

function is_bytes ( a ) {
    return ( a instanceof Uint8Array );
}

function is_typed_array ( a ) {
    return ( a instanceof Int8Array ) || ( a instanceof Uint8Array )
        || ( a instanceof Int16Array ) || ( a instanceof Uint16Array )
        || ( a instanceof Int32Array ) || ( a instanceof Uint32Array )
        || ( a instanceof Float32Array )
        || ( a instanceof Float64Array );
}

function _heap_init ( constructor, options ) {
    var heap = options.heap,
        size = heap ? heap.byteLength : options.heapSize || 65536;

    if ( size & 0xfff || size <= 0 )
        throw new Error("heap size must be a positive integer and a multiple of 4096");

    heap = heap || new constructor( new ArrayBuffer(size) );

    return heap;
}

function _heap_write ( heap, hpos, data, dpos, dlen ) {
    var hlen = heap.length - hpos,
        wlen = ( hlen < dlen ) ? hlen : dlen;

    heap.set( data.subarray( dpos, dpos+wlen ), hpos );

    return wlen;
}
var _global_console = global.console;

var _secure_origin = !global.location.protocol.search( /https:|file:|chrome:|chrome-extension:/ );

if ( !_secure_origin && _global_console !== undefined ) {
    _global_console.warn("asmCrypto seems to be load from an insecure origin; this may cause to MitM-attack vulnerability. Consider using secure transport protocol.");
}
/**
 * Util exports
 */

exports.string_to_bytes = string_to_bytes;
exports.hex_to_bytes = hex_to_bytes;
exports.base64_to_bytes = base64_to_bytes;
exports.bytes_to_string = bytes_to_string;
exports.bytes_to_hex = bytes_to_hex;
exports.bytes_to_base64 = bytes_to_base64;
/**
 * Error definitions
 */

global.IllegalStateError = IllegalStateError;
global.IllegalArgumentError = IllegalArgumentError;
global.SecurityError = SecurityError;
/**
 * @file {@link http://asmjs.org Asm.js} implementation of the {@link https://en.wikipedia.org/wiki/Advanced_Encryption_Standard Advanced Encryption Standard}.
 * @author Artem S Vybornov <vybornov@gmail.com>
 * @license MIT
 */
var AES_asm = function () {
    "use strict";

    /**
     * Galois Field stuff init flag
     */
    var ginit_done = false;

    /**
     * Galois Field exponentiation and logarithm tables for 3 (the generator)
     */
    var gexp3, glog3;

    /**
     * Init Galois Field tables
     */
    function ginit () {
        gexp3 = [],
        glog3 = [];

        var a = 1, c, d;
        for ( c = 0; c < 255; c++ ) {
            gexp3[c] = a;

            // Multiply by three
            d = a & 0x80, a <<= 1, a &= 255;
            if ( d === 0x80 ) a ^= 0x1b;
            a ^= gexp3[c];

            // Set the log table value
            glog3[gexp3[c]] = c;
        }
        gexp3[255] = gexp3[0];
        glog3[0] = 0;

        ginit_done = true;
    }

    /**
     * Galois Field multiplication
     * @param {int} a
     * @param {int} b
     * @return {int}
     */
    function gmul ( a, b ) {
        var c = gexp3[ ( glog3[a] + glog3[b] ) % 255 ];
        if ( a === 0 || b === 0 ) c = 0;
        return c;
    }

    /**
     * Galois Field reciprocal
     * @param {int} a
     * @return {int}
     */
    function ginv ( a ) {
        var i = gexp3[ 255 - glog3[a] ];
        if ( a === 0 ) i = 0;
        return i;
    }

    /**
     * AES stuff init flag
     */
    var aes_init_done = false;

    /**
     * Encryption, Decryption, S-Box and KeyTransform tables
     */
    var aes_sbox, aes_sinv, aes_enc, aes_dec;

    /**
     * Init AES tables
     */
    function aes_init () {
        if ( !ginit_done ) ginit();

        // Calculates AES S-Box value
        function _s ( a ) {
            var c, s, x;
            s = x = ginv(a);
            for ( c = 0; c < 4; c++ ) {
                s = ( (s << 1) | (s >>> 7) ) & 255;
                x ^= s;
            }
            x ^= 99;
            return x;
        }

        // Tables
        aes_sbox = [],
        aes_sinv = [],
        aes_enc = [ [], [], [], [] ],
        aes_dec = [ [], [], [], [] ];

        for ( var i = 0; i < 256; i++ ) {
            var s = _s(i);

            // S-Box and its inverse
            aes_sbox[i]  = s;
            aes_sinv[s]  = i;

            // Ecryption and Decryption tables
            aes_enc[0][i] = ( gmul( 2, s ) << 24 )  | ( s << 16 )            | ( s << 8 )             | gmul( 3, s );
            aes_dec[0][s] = ( gmul( 14, i ) << 24 ) | ( gmul( 9, i ) << 16 ) | ( gmul( 13, i ) << 8 ) | gmul( 11, i );
            // Rotate tables
            for ( var t = 1; t < 4; t++ ) {
                aes_enc[t][i] = ( aes_enc[t-1][i] >>> 8 ) | ( aes_enc[t-1][i] << 24 );
                aes_dec[t][s] = ( aes_dec[t-1][s] >>> 8 ) | ( aes_dec[t-1][s] << 24 );
            }
        }
    }

    /**
     * Asm.js module constructor.
     *
     * <p>
     * Heap buffer layout by offset:
     * <pre>
     * 0x0000   encryption key schedule
     * 0x0400   decryption key schedule
     * 0x0800   sbox
     * 0x0c00   inv sbox
     * 0x1000   encryption tables
     * 0x2000   decryption tables
     * 0x3000   reserved (future GCM multiplication lookup table)
     * 0x4000   data
     * </pre>
     * Don't touch anything before <code>0x400</code>.
     * </p>
     *
     * @alias AES_asm
     * @class
     * @param {GlobalScope} stdlib - global scope object (e.g. <code>window</code>)
     * @param {Object} foreign - <i>ignored</i>
     * @param {ArrayBuffer} buffer - heap buffer to link with
     */
    var wrapper = function ( stdlib, foreign, buffer ) {
        // Init AES stuff for the first time
        if ( !aes_init_done ) aes_init();

        // Fill up AES tables
        var heap = new Uint32Array(buffer);
        heap.set( aes_sbox, 0x0800>>2 );
        heap.set( aes_sinv, 0x0c00>>2 );
        for ( var i = 0; i < 4; i++ ) {
            heap.set( aes_enc[i], ( 0x1000 + 0x400 * i )>>2 );
            heap.set( aes_dec[i], ( 0x2000 + 0x400 * i )>>2 );
        }

        /**
         * Calculate AES key schedules.
         * @instance
         * @memberof AES_asm
         * @param {int} ks - key size, 4/6/8 (for 128/192/256-bit key correspondingly)
         * @param {int} k0..k7 - key vector components
         */
        function set_key ( ks, k0, k1, k2, k3, k4, k5, k6, k7 ) {
            var ekeys = heap.subarray( 0x000, 60 ),
                dkeys = heap.subarray( 0x100, 0x100+60 );

            // Encryption key schedule
            ekeys.set( [ k0, k1, k2, k3, k4, k5, k6, k7 ] );
            for ( var i = ks, rcon = 1; i < 4*ks+28; i++ ) {
                var k = ekeys[i-1];
                if ( ( i % ks === 0 ) || ( ks === 8 && i % ks === 4 ) ) {
                    k = aes_sbox[k>>>24]<<24 ^ aes_sbox[k>>>16&255]<<16 ^ aes_sbox[k>>>8&255]<<8 ^ aes_sbox[k&255];
                }
                if ( i % ks === 0 ) {
                    k = (k << 8) ^ (k >>> 24) ^ (rcon << 24);
                    rcon = (rcon << 1) ^ ( (rcon & 0x80) ? 0x1b : 0 );
                }
                ekeys[i] = ekeys[i-ks] ^ k;
            }

            // Decryption key schedule
            for ( var j = 0; j < i; j += 4 ) {
                for ( var jj = 0; jj < 4; jj++ ) {
                    var k = ekeys[i-(4+j)+(4-jj)%4];
                    if ( j < 4 || j >= i-4 ) {
                        dkeys[j+jj] = k;
                    } else {
                        dkeys[j+jj] = aes_dec[0][aes_sbox[k>>>24]]
                                    ^ aes_dec[1][aes_sbox[k>>>16&255]]
                                    ^ aes_dec[2][aes_sbox[k>>>8&255]]
                                    ^ aes_dec[3][aes_sbox[k&255]];
                    }
                }
            }

            // Set rounds number
            asm.set_rounds( ks + 5 );
        }

        var asm = function ( stdlib, foreign, buffer ) {
            "use asm";

            var S0 = 0, S1 = 0, S2 = 0, S3 = 0,
                I0 = 0, I1 = 0, I2 = 0, I3 = 0,
                N0 = 0, N1 = 0, N2 = 0, N3 = 0,
                M0 = 0, M1 = 0, M2 = 0, M3 = 0,
                H0 = 0, H1 = 0, H2 = 0, H3 = 0,
                R = 0;

            var HEAP = new stdlib.Uint32Array(buffer),
                DATA = new stdlib.Uint8Array(buffer);

            /**
             * AES core
             * @param {int} k - precomputed key schedule offset
             * @param {int} s - precomputed sbox table offset
             * @param {int} t - precomputed round table offset
             * @param {int} r - number of inner rounds to perform
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _core ( k, s, t, r, x0, x1, x2, x3 ) {
                k = k|0;
                s = s|0;
                t = t|0;
                r = r|0;
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t1 = 0, t2 = 0, t3 = 0,
                    y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                    i = 0;

                t1 = t|0x400, t2 = t|0x800, t3 = t|0xc00;

                // round 0
                x0 = x0 ^ HEAP[(k|0)>>2],
                x1 = x1 ^ HEAP[(k|4)>>2],
                x2 = x2 ^ HEAP[(k|8)>>2],
                x3 = x3 ^ HEAP[(k|12)>>2];

                // round 1..r
                for ( i = 16; (i|0) <= (r<<4); i = (i+16)|0 ) {
                    y0 = HEAP[(t|x0>>22&1020)>>2] ^ HEAP[(t1|x1>>14&1020)>>2] ^ HEAP[(t2|x2>>6&1020)>>2] ^ HEAP[(t3|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                    y1 = HEAP[(t|x1>>22&1020)>>2] ^ HEAP[(t1|x2>>14&1020)>>2] ^ HEAP[(t2|x3>>6&1020)>>2] ^ HEAP[(t3|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                    y2 = HEAP[(t|x2>>22&1020)>>2] ^ HEAP[(t1|x3>>14&1020)>>2] ^ HEAP[(t2|x0>>6&1020)>>2] ^ HEAP[(t3|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                    y3 = HEAP[(t|x3>>22&1020)>>2] ^ HEAP[(t1|x0>>14&1020)>>2] ^ HEAP[(t2|x1>>6&1020)>>2] ^ HEAP[(t3|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
                    x0 = y0, x1 = y1, x2 = y2, x3 = y3;
                }

                // final round
                S0 = HEAP[(s|x0>>22&1020)>>2]<<24 ^ HEAP[(s|x1>>14&1020)>>2]<<16 ^ HEAP[(s|x2>>6&1020)>>2]<<8 ^ HEAP[(s|x3<<2&1020)>>2] ^ HEAP[(k|i|0)>>2],
                S1 = HEAP[(s|x1>>22&1020)>>2]<<24 ^ HEAP[(s|x2>>14&1020)>>2]<<16 ^ HEAP[(s|x3>>6&1020)>>2]<<8 ^ HEAP[(s|x0<<2&1020)>>2] ^ HEAP[(k|i|4)>>2],
                S2 = HEAP[(s|x2>>22&1020)>>2]<<24 ^ HEAP[(s|x3>>14&1020)>>2]<<16 ^ HEAP[(s|x0>>6&1020)>>2]<<8 ^ HEAP[(s|x1<<2&1020)>>2] ^ HEAP[(k|i|8)>>2],
                S3 = HEAP[(s|x3>>22&1020)>>2]<<24 ^ HEAP[(s|x0>>14&1020)>>2]<<16 ^ HEAP[(s|x1>>6&1020)>>2]<<8 ^ HEAP[(s|x2<<2&1020)>>2] ^ HEAP[(k|i|12)>>2];
            }

            /**
             * ECB mode encryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ecb_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    x0,
                    x1,
                    x2,
                    x3
                );
            }

            /**
             * ECB mode decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ecb_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t = 0;

                _core(
                    0x0400, 0x0c00, 0x2000,
                    R,
                    x0,
                    x3,
                    x2,
                    x1
                );

                t = S1, S1 = S3, S3 = t;
            }


            /**
             * CBC mode encryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cbc_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0 ^ x0,
                    I1 ^ x1,
                    I2 ^ x2,
                    I3 ^ x3
                );

                I0 = S0,
                I1 = S1,
                I2 = S2,
                I3 = S3;
            }

            /**
             * CBC mode decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cbc_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var t = 0;

                _core(
                    0x0400, 0x0c00, 0x2000,
                    R,
                    x0,
                    x3,
                    x2,
                    x1
                );

                t = S1, S1 = S3, S3 = t;

                S0 = S0 ^ I0,
                S1 = S1 ^ I1,
                S2 = S2 ^ I2,
                S3 = S3 ^ I3;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * CFB mode encryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cfb_enc ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                I0 = S0 = S0 ^ x0,
                I1 = S1 = S1 ^ x1,
                I2 = S2 = S2 ^ x2,
                I3 = S3 = S3 ^ x3;
            }


            /**
             * CFB mode decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _cfb_dec ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;

                I0 = x0,
                I1 = x1,
                I2 = x2,
                I3 = x3;
            }

            /**
             * OFB mode encryption / decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ofb ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    I0,
                    I1,
                    I2,
                    I3
                );

                I0 = S0,
                I1 = S1,
                I2 = S2,
                I3 = S3;

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;
            }

            /**
             * CTR mode encryption / decryption
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _ctr ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                _core(
                    0x0000, 0x0800, 0x1000,
                    R,
                    N0,
                    N1,
                    N2,
                    N3
                );

                N3 = ( ~M3 & N3 ) | M3 & ( N3 + 1 ),
                N2 = ( ~M2 & N2 ) | M2 & ( N2 + ( (N3|0) == 0 ) ),
                N1 = ( ~M1 & N1 ) | M1 & ( N1 + ( (N2|0) == 0 ) ),
                N0 = ( ~M0 & N0 ) | M0 & ( N0 + ( (N1|0) == 0 ) );

                S0 = S0 ^ x0,
                S1 = S1 ^ x1,
                S2 = S2 ^ x2,
                S3 = S3 ^ x3;
            }

            /**
             * GCM mode MAC calculation
             * @param {int} x0..x3 - 128-bit input block vector
             */
            function _gcm_mac ( x0, x1, x2, x3 ) {
                x0 = x0|0;
                x1 = x1|0;
                x2 = x2|0;
                x3 = x3|0;

                var y0 = 0, y1 = 0, y2 = 0, y3 = 0,
                    z0 = 0, z1 = 0, z2 = 0, z3 = 0,
                    i = 0, c = 0;

                x0 = x0 ^ I0,
                x1 = x1 ^ I1,
                x2 = x2 ^ I2,
                x3 = x3 ^ I3;

                y0 = H0|0,
                y1 = H1|0,
                y2 = H2|0,
                y3 = H3|0;

                for ( ; (i|0) < 128; i = (i + 1)|0 ) {
                    if ( y0 >>> 31 ) {
                        z0 = z0 ^ x0,
                        z1 = z1 ^ x1,
                        z2 = z2 ^ x2,
                        z3 = z3 ^ x3;
                    }

                    y0 = (y0 << 1) | (y1 >>> 31),
                    y1 = (y1 << 1) | (y2 >>> 31),
                    y2 = (y2 << 1) | (y3 >>> 31),
                    y3 = (y3 << 1);

                    c = x3 & 1;

                    x3 = (x3 >>> 1) | (x2 << 31),
                    x2 = (x2 >>> 1) | (x1 << 31),
                    x1 = (x1 >>> 1) | (x0 << 31),
                    x0 = (x0 >>> 1);

                    if ( c ) x0 = x0 ^ 0xe1000000;
                }

                I0 = z0,
                I1 = z1,
                I2 = z2,
                I3 = z3;
            }

            /**
             * Set the internal rounds number.
             * @instance
             * @memberof AES_asm
             * @param {int} r - number if inner AES rounds
             */
            function set_rounds ( r ) {
                r = r|0;
                R = r;
            }

            /**
             * Populate the internal state of the module.
             * @instance
             * @memberof AES_asm
             * @param {int} s0...s3 - state vector
             */
            function set_state ( s0, s1, s2, s3 ) {
                s0 = s0|0;
                s1 = s1|0;
                s2 = s2|0;
                s3 = s3|0;

                S0 = s0,
                S1 = s1,
                S2 = s2,
                S3 = s3;
            }

            /**
             * Populate the internal iv of the module.
             * @instance
             * @memberof AES_asm
             * @param {int} i0...i3 - iv vector
             */
            function set_iv ( i0, i1, i2, i3 ) {
                i0 = i0|0;
                i1 = i1|0;
                i2 = i2|0;
                i3 = i3|0;

                I0 = i0,
                I1 = i1,
                I2 = i2,
                I3 = i3;
            }

            /**
             * Set nonce for CTR-family modes.
             * @instance
             * @memberof AES_asm
             * @param {int} n0..n3 - nonce vector
             */
            function set_nonce ( n0, n1, n2, n3 ) {
                n0 = n0|0;
                n1 = n1|0;
                n2 = n2|0;
                n3 = n3|0;

                N0 = n0,
                N1 = n1,
                N2 = n2,
                N3 = n3;
            }

            /**
             * Set counter mask for CTR-family modes.
             * @instance
             * @memberof AES_asm
             * @param {int} m0...m3 - counter mask vector
             */
            function set_mask ( m0, m1, m2, m3 ) {
                m0 = m0|0;
                m1 = m1|0;
                m2 = m2|0;
                m3 = m3|0;

                M0 = m0,
                M1 = m1,
                M2 = m2,
                M3 = m3;
            }

            /**
             * Set counter for CTR-family modes.
             * @instance
             * @memberof AES_asm
             * @param {int} c0...c3 - counter vector
             */
            function set_counter ( c0, c1, c2, c3 ) {
                c0 = c0|0;
                c1 = c1|0;
                c2 = c2|0;
                c3 = c3|0;

                N3 = ( ~M3 & N3 ) | M3 & c3,
                N2 = ( ~M2 & N2 ) | M2 & c2,
                N1 = ( ~M1 & N1 ) | M1 & c1,
                N0 = ( ~M0 & N0 ) | M0 & c0;
            }

            /**
             * Store the internal state vector into the heap.
             * @instance
             * @memberof AES_asm
             * @param {int} pos - offset where to put the data
             * @return {int} The number of bytes have been written into the heap, always 16.
             */
            function get_state ( pos ) {
                pos = pos|0;

                if ( pos & 15 ) return -1;

                DATA[pos|0] = S0>>>24,
                DATA[pos|1] = S0>>>16&255,
                DATA[pos|2] = S0>>>8&255,
                DATA[pos|3] = S0&255,
                DATA[pos|4] = S1>>>24,
                DATA[pos|5] = S1>>>16&255,
                DATA[pos|6] = S1>>>8&255,
                DATA[pos|7] = S1&255,
                DATA[pos|8] = S2>>>24,
                DATA[pos|9] = S2>>>16&255,
                DATA[pos|10] = S2>>>8&255,
                DATA[pos|11] = S2&255,
                DATA[pos|12] = S3>>>24,
                DATA[pos|13] = S3>>>16&255,
                DATA[pos|14] = S3>>>8&255,
                DATA[pos|15] = S3&255;

                return 16;
            }

            /**
             * Store the internal iv vector into the heap.
             * @instance
             * @memberof AES_asm
             * @param {int} pos - offset where to put the data
             * @return {int} The number of bytes have been written into the heap, always 16.
             */
            function get_iv ( pos ) {
                pos = pos|0;

                if ( pos & 15 ) return -1;

                DATA[pos|0] = I0>>>24,
                DATA[pos|1] = I0>>>16&255,
                DATA[pos|2] = I0>>>8&255,
                DATA[pos|3] = I0&255,
                DATA[pos|4] = I1>>>24,
                DATA[pos|5] = I1>>>16&255,
                DATA[pos|6] = I1>>>8&255,
                DATA[pos|7] = I1&255,
                DATA[pos|8] = I2>>>24,
                DATA[pos|9] = I2>>>16&255,
                DATA[pos|10] = I2>>>8&255,
                DATA[pos|11] = I2&255,
                DATA[pos|12] = I3>>>24,
                DATA[pos|13] = I3>>>16&255,
                DATA[pos|14] = I3>>>8&255,
                DATA[pos|15] = I3&255;

                return 16;
            }

            /**
             * GCM initialization.
             * @instance
             * @memberof AES_asm
             */
            function gcm_init ( ) {
                _ecb_enc( 0, 0, 0, 0 );
                H0 = S0,
                H1 = S1,
                H2 = S2,
                H3 = S3;
            }

            /**
             * Perform ciphering operation on the supplied data.
             * @instance
             * @memberof AES_asm
             * @param {int} mode - block cipher mode (see {@link AES_asm} mode constants)
             * @param {int} pos - offset of the data being processed
             * @param {int} len - length of the data being processed
             * @return {int} Actual amount of data have been processed.
             */
            function cipher ( mode, pos, len ) {
                mode = mode|0;
                pos = pos|0;
                len = len|0;

                var ret = 0;

                if ( pos & 15 ) return -1;

                while ( (len|0) >= 16 ) {
                    _cipher_modes[mode&7](
                        DATA[pos|0]<<24 | DATA[pos|1]<<16 | DATA[pos|2]<<8 | DATA[pos|3],
                        DATA[pos|4]<<24 | DATA[pos|5]<<16 | DATA[pos|6]<<8 | DATA[pos|7],
                        DATA[pos|8]<<24 | DATA[pos|9]<<16 | DATA[pos|10]<<8 | DATA[pos|11],
                        DATA[pos|12]<<24 | DATA[pos|13]<<16 | DATA[pos|14]<<8 | DATA[pos|15]
                    );

                    DATA[pos|0] = S0>>>24,
                    DATA[pos|1] = S0>>>16&255,
                    DATA[pos|2] = S0>>>8&255,
                    DATA[pos|3] = S0&255,
                    DATA[pos|4] = S1>>>24,
                    DATA[pos|5] = S1>>>16&255,
                    DATA[pos|6] = S1>>>8&255,
                    DATA[pos|7] = S1&255,
                    DATA[pos|8] = S2>>>24,
                    DATA[pos|9] = S2>>>16&255,
                    DATA[pos|10] = S2>>>8&255,
                    DATA[pos|11] = S2&255,
                    DATA[pos|12] = S3>>>24,
                    DATA[pos|13] = S3>>>16&255,
                    DATA[pos|14] = S3>>>8&255,
                    DATA[pos|15] = S3&255;

                    ret = (ret + 16)|0,
                    pos = (pos + 16)|0,
                    len = (len - 16)|0;
                }

                return ret|0;
            }

            /**
             * Calculates MAC of the supplied data.
             * @instance
             * @memberof AES_asm
             * @param {int} mode - block cipher mode (see {@link AES_asm} mode constants)
             * @param {int} pos - offset of the data being processed
             * @param {int} len - length of the data being processed
             * @return {int} Actual amount of data have been processed.
             */
            function mac ( mode, pos, len ) {
                mode = mode|0;
                pos = pos|0;
                len = len|0;

                var ret = 0;

                if ( pos & 15 ) return -1;

                while ( (len|0) >= 16 ) {
                    _mac_modes[mode&1](
                        DATA[pos|0]<<24 | DATA[pos|1]<<16 | DATA[pos|2]<<8 | DATA[pos|3],
                        DATA[pos|4]<<24 | DATA[pos|5]<<16 | DATA[pos|6]<<8 | DATA[pos|7],
                        DATA[pos|8]<<24 | DATA[pos|9]<<16 | DATA[pos|10]<<8 | DATA[pos|11],
                        DATA[pos|12]<<24 | DATA[pos|13]<<16 | DATA[pos|14]<<8 | DATA[pos|15]
                    );

                    ret = (ret + 16)|0,
                    pos = (pos + 16)|0,
                    len = (len - 16)|0;
                }

                return ret|0;
            }

            /**
             * AES cipher modes table (virual methods)
             */
            var _cipher_modes = [ _ecb_enc, _ecb_dec, _cbc_enc, _cbc_dec, _cfb_enc, _cfb_dec, _ofb, _ctr ];

            /**
             * AES MAC modes table (virual methods)
             */
            var _mac_modes = [ _cbc_enc, _gcm_mac ];

            /**
             * Asm.js module exports
             */
            return {
                set_rounds: set_rounds,
                set_state:  set_state,
                set_iv:     set_iv,
                set_nonce:  set_nonce,
                set_mask:   set_mask,
                set_counter:set_counter,
                get_state:  get_state,
                get_iv:     get_iv,
                gcm_init:   gcm_init,
                cipher:     cipher,
                mac:        mac
            };
        }( stdlib, foreign, buffer );

        asm.set_key = set_key;

        return asm;
    };

    /**
     * AES enciphering mode constants
     * @enum {int}
     * @const
     */
    wrapper.ENC = {
        ECB: 0,
        CBC: 2,
        CFB: 4,
        OFB: 6,
        CTR: 7
    },

    /**
     * AES deciphering mode constants
     * @enum {int}
     * @const
     */
    wrapper.DEC = {
        ECB: 1,
        CBC: 3,
        CFB: 5,
        OFB: 6,
        CTR: 7
    },

    /**
     * AES MAC mode constants
     * @enum {int}
     * @const
     */
    wrapper.MAC = {
        CBC: 0,
        GCM: 1
    };

    /**
     * Heap data offset
     * @type {int}
     * @const
     */
    wrapper.HEAP_DATA = 0x4000;

    return wrapper;
}();
function AES ( options ) {
    options = options || {};

    this.heap = _heap_init( Uint8Array, options ).subarray( AES_asm.HEAP_DATA );
    this.asm = options.asm || AES_asm( global, null, this.heap.buffer );
    this.mode = null;
    this.key = null;

    this.reset( options );
}

function AES_set_key ( key ) {
    if ( key !== undefined ) {
        if ( is_buffer(key) || is_bytes(key) ) {
            key = new Uint8Array(key);
        }
        else if ( is_string(key) ) {
            key = string_to_bytes(key);
        }
        else {
            throw new TypeError("unexpected key type");
        }

        var keylen = key.length;
        if ( keylen !== 16 && keylen !== 24 && keylen !== 32 )
            throw new IllegalArgumentError("illegal key size");

        var keyview = new DataView( key.buffer, key.byteOffset, key.byteLength );
        this.asm.set_key(
            keylen >> 2,
            keyview.getUint32(0),
            keyview.getUint32(4),
            keyview.getUint32(8),
            keyview.getUint32(12),
            keylen > 16 ? keyview.getUint32(16) : 0,
            keylen > 16 ? keyview.getUint32(20) : 0,
            keylen > 24 ? keyview.getUint32(24) : 0,
            keylen > 24 ? keyview.getUint32(28) : 0
        );

        this.key = key;
    }
    else if ( !this.key ) {
        throw new Error("key is required");
    }
}

function AES_set_iv ( iv ) {
    if ( iv !== undefined ) {
        if ( is_buffer(iv) || is_bytes(iv) ) {
            iv = new Uint8Array(iv);
        }
        else if ( is_string(iv) ) {
            iv = string_to_bytes(iv);
        }
        else {
            throw new TypeError("unexpected iv type");
        }

        if ( iv.length !== 16 )
            throw new IllegalArgumentError("illegal iv size");

        var ivview = new DataView( iv.buffer, iv.byteOffset, iv.byteLength );

        this.iv = iv;
        this.asm.set_iv( ivview.getUint32(0), ivview.getUint32(4), ivview.getUint32(8), ivview.getUint32(12) );
    }
    else {
        this.iv = null;
        this.asm.set_iv( 0, 0, 0, 0 );
    }
}

function AES_set_padding ( padding ) {
    if ( padding !== undefined ) {
        this.padding = !!padding;
    }
    else {
        this.padding = true;
    }
}

function AES_reset ( options ) {
    options = options || {};

    this.result = null;
    this.pos = 0;
    this.len = 0;

    AES_set_key.call( this, options.key );
    if ( this.hasOwnProperty('iv') ) AES_set_iv.call( this, options.iv );
    if ( this.hasOwnProperty('padding') ) AES_set_padding.call( this, options.padding );

    return this;
}

function AES_Encrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.ENC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        dpos = 0,
        dlen = data.length || 0,
        rpos = 0,
        rlen = (len + dlen) & -16,
        wlen = 0;

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( amode, hpos + pos, len );

        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_Encrypt_finish ( data ) {
    var presult = null,
        prlen = 0;

    if ( data !== undefined ) {
        presult = AES_Encrypt_process.call( this, data ).result;
        prlen = presult.length;
    }

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.ENC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        plen = 16 - len % 16,
        rlen = len;

    if ( this.hasOwnProperty('padding') ) {
        if ( this.padding ) {
            for ( var p = 0; p < plen; ++p ) heap[ pos + len + p ] = plen;
            len += plen;
            rlen = len;
        }
        else if ( len % 16 ) {
            throw new IllegalArgumentError("data length must be a multiple of the block size");
        }
    }
    else {
        len += plen;
    }

    var result = new Uint8Array( prlen + rlen );

    if ( prlen ) result.set( presult );

    if ( len ) asm.cipher( amode, hpos + pos, len );

    if ( rlen ) result.set( heap.subarray( pos, pos + rlen ), prlen );

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
}

function AES_Decrypt_process ( data ) {
    if ( is_string(data) )
        data = string_to_bytes(data);

    if ( is_buffer(data) )
        data = new Uint8Array(data);

    if ( !is_bytes(data) )
        throw new TypeError("data isn't of expected type");

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.DEC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        dpos = 0,
        dlen = data.length || 0,
        rpos = 0,
        rlen = (len + dlen) & -16,
        plen = 0,
        wlen = 0;

    if ( this.hasOwnProperty('padding') && this.padding ) {
        plen = len + dlen - rlen || 16;
        rlen -= plen;
    }

    var result = new Uint8Array(rlen);

    while ( dlen > 0 ) {
        wlen = _heap_write( heap, pos+len, data, dpos, dlen );
        len  += wlen;
        dpos += wlen;
        dlen -= wlen;

        wlen = asm.cipher( amode, hpos + pos, len - ( !dlen ? plen : 0 ) );

        if ( wlen ) result.set( heap.subarray( pos, pos + wlen ), rpos );
        rpos += wlen;

        if ( wlen < len ) {
            pos += wlen;
            len -= wlen;
        } else {
            pos = 0;
            len = 0;
        }
    }

    this.result = result;
    this.pos = pos;
    this.len = len;

    return this;
}

function AES_Decrypt_finish ( data ) {
    var presult = null,
        prlen = 0;

    if ( data !== undefined ) {
        presult = AES_Decrypt_process.call( this, data ).result;
        prlen = presult.length;
    }

    var asm = this.asm,
        heap = this.heap,
        amode = AES_asm.DEC[this.mode],
        hpos = AES_asm.HEAP_DATA,
        pos = this.pos,
        len = this.len,
        rlen = len;

    if ( len > 0 ) {
        if ( len % 16 ) {
            if ( this.hasOwnProperty('padding') ) {
                throw new IllegalArgumentError("data length must be a multiple of the block size");
            } else {
                len += 16 - len % 16;
            }
        }

        asm.cipher( amode, hpos + pos, len );

        if ( this.hasOwnProperty('padding') && this.padding ) {
            var pad = heap[ pos + rlen - 1 ];
            if ( pad < 1 || pad > 16 || pad > rlen )
                throw new SecurityError("bad padding");

            var pcheck = 0;
            for ( var i = pad; i > 1; i-- ) pcheck |= pad ^ heap[ pos + rlen - i ];
            if ( pcheck )
                throw new SecurityError("bad padding");

            rlen -= pad;
        }
    }

    var result = new Uint8Array( prlen + rlen );

    if ( prlen > 0 ) {
        result.set( presult );
    }

    if ( rlen > 0 ) {
        result.set( heap.subarray( pos, pos + rlen ), prlen );
    }

    this.result = result;
    this.pos = 0;
    this.len = 0;

    return this;
}
/**
 * Electronic Code Book Mode (ECB)
 */

function AES_ECB ( options ) {
    this.padding = true;

    AES.call( this, options );

    this.mode = 'ECB';
}

var AES_ECB_prototype = AES_ECB.prototype;
AES_ECB_prototype.BLOCK_SIZE = 16;
AES_ECB_prototype.reset = AES_reset;
AES_ECB_prototype.encrypt = AES_Encrypt_finish;
AES_ECB_prototype.decrypt = AES_Decrypt_finish;

function AES_ECB_Encrypt ( options ) {
    AES_ECB.call( this, options );
}

var AES_ECB_Encrypt_prototype = AES_ECB_Encrypt.prototype;
AES_ECB_Encrypt_prototype.BLOCK_SIZE = 16;
AES_ECB_Encrypt_prototype.reset = AES_reset;
AES_ECB_Encrypt_prototype.process = AES_Encrypt_process;
AES_ECB_Encrypt_prototype.finish = AES_Encrypt_finish;

function AES_ECB_Decrypt ( options ) {
    AES_ECB.call( this, options );
}

var AES_ECB_Decrypt_prototype = AES_ECB_Decrypt.prototype;
AES_ECB_Decrypt_prototype.BLOCK_SIZE = 16;
AES_ECB_Decrypt_prototype.reset = AES_reset;
AES_ECB_Decrypt_prototype.process = AES_Decrypt_process;
AES_ECB_Decrypt_prototype.finish = AES_Decrypt_finish;
/**
 * AES-ECB exports
 */

function AES_ECB_encrypt_bytes ( data, key, padding ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_ECB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding } ).encrypt(data).result;
}

function AES_ECB_decrypt_bytes ( data, key, padding ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_ECB( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding } ).decrypt(data).result;
}

exports.AES_ECB = AES_ECB;
exports.AES_ECB.encrypt = AES_ECB_encrypt_bytes;
exports.AES_ECB.decrypt = AES_ECB_decrypt_bytes;

exports.AES_ECB.Encrypt = AES_ECB_Encrypt;
exports.AES_ECB.Decrypt = AES_ECB_Decrypt;
/**
 * Cipher Block Chaining Mode (CBC)
 */

function AES_CBC ( options ) {
    this.padding = true;
    this.iv = null;

    AES.call( this, options );

    this.mode = 'CBC';
}

var AES_CBC_prototype = AES_CBC.prototype;
AES_CBC_prototype.BLOCK_SIZE = 16;
AES_CBC_prototype.reset = AES_reset;
AES_CBC_prototype.encrypt = AES_Encrypt_finish;
AES_CBC_prototype.decrypt = AES_Decrypt_finish;

function AES_CBC_Encrypt ( options ) {
    AES_CBC.call( this, options );
}

var AES_CBC_Encrypt_prototype = AES_CBC_Encrypt.prototype;
AES_CBC_Encrypt_prototype.BLOCK_SIZE = 16;
AES_CBC_Encrypt_prototype.reset = AES_reset;
AES_CBC_Encrypt_prototype.process = AES_Encrypt_process;
AES_CBC_Encrypt_prototype.finish = AES_Encrypt_finish;

function AES_CBC_Decrypt ( options ) {
    AES_CBC.call( this, options );
}

var AES_CBC_Decrypt_prototype = AES_CBC_Decrypt.prototype;
AES_CBC_Decrypt_prototype.BLOCK_SIZE = 16;
AES_CBC_Decrypt_prototype.reset = AES_reset;
AES_CBC_Decrypt_prototype.process = AES_Decrypt_process;
AES_CBC_Decrypt_prototype.finish = AES_Decrypt_finish;
// shared asm.js module and heap
var _AES_heap_instance = new Uint8Array(0x100000),
    _AES_asm_instance  = AES_asm( global, null, _AES_heap_instance.buffer );
/**
 * AES-CBC exports
 */

function AES_CBC_encrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CBC( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding, iv: iv } ).encrypt(data).result;
}

function AES_CBC_decrypt_bytes ( data, key, padding, iv ) {
    if ( data === undefined ) throw new SyntaxError("data required");
    if ( key === undefined ) throw new SyntaxError("key required");
    return new AES_CBC( { heap: _AES_heap_instance, asm: _AES_asm_instance, key: key, padding: padding, iv: iv } ).decrypt(data).result;
}

exports.AES_CBC = AES_CBC;
exports.AES_CBC.encrypt = AES_CBC_encrypt_bytes;
exports.AES_CBC.decrypt = AES_CBC_decrypt_bytes;

exports.AES_CBC.Encrypt = AES_CBC_Encrypt;
exports.AES_CBC.Decrypt = AES_CBC_Decrypt;
