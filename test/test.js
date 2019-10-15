'use strict';

const fs = require('fs');
const JWT = require('../lib/jwt.js');

const jwt = new JWT(
{
    HS512: 'P455PHR45E',
    HS384: 'P455PHR45E',
    HS256: 'P455PHR45E',
    RS512:
    {
        key: fs.readFileSync( __dirname + '/keys/rsa.2048.key' ),
        pub: fs.readFileSync( __dirname + '/keys/rsa.2048.pub' )
    },
    RS384:
    {
        key: fs.readFileSync( __dirname + '/keys/rsa.2048.key' ),
        pub: fs.readFileSync( __dirname + '/keys/rsa.2048.pub' )
    },
    RS256:
    {
        key: fs.readFileSync( __dirname + '/keys/rsa.2048.key' ),
        pub: fs.readFileSync( __dirname + '/keys/rsa.2048.pub' )
    },
    ES512:
    {
        key: fs.readFileSync( __dirname + '/keys/ec.521.key' ),
        pub: fs.readFileSync( __dirname + '/keys/ec.521.pub' )
    },
    ES384:
    {
        key: fs.readFileSync( __dirname + '/keys/ec.384.key' ),
        pub: fs.readFileSync( __dirname + '/keys/ec.384.pub' )
    },
    ES256:
    {
        key: fs.readFileSync( __dirname + '/keys/ec.256.key' ),
        pub: fs.readFileSync( __dirname + '/keys/ec.256.pub' )
    }
});

let t = jwt.create({ janko: 'hrasko' }, 'ES384' );

console.log( t );

let p = jwt.parse( t );

console.log( p );

let CNT = 10000, s = true;

/*let t = jwt.create({ roles: ['hrasko'], prd: 'mak' }, 'HS512' );

console.log( t );

console.log( jwt.parse( t ) );

process.exit();

let start = process.hrtime();

for( let i = 0; i < CNT; ++i )
{
    s = s & jwt.parse( t ).signature;
}

let end = process.hrtime( start );

console.log( CNT / ( end[0] + end[1] / 1e9 ));

/**/

//for( let alg of [ 'HS512', 'HS384', 'HS256', 'RS512', 'RS384', 'RS256', 'ES512', 'ES384', 'ES256' ])


/*iss : string optional (Issuer)
sub : string optional (Subject)
aud : strings optional (Audience)
exp : number optional (Expiration Time)
nbf : number optional (Not Before)
iat : number optional (Issued At)
jti : string optional (JWT ID - uniqueID)*/


let alg = 'HS256';
{
    let t = jwt.create(
    {
      "sub": "1234567890",
      "name": "John Doe",
      "admin": true,
      "iat": 1516239022
    }, alg );

    let start = process.hrtime();

    for( let i = 0; i < CNT; ++i )
    {
        s = s & jwt.parse( t ).ok;
    }

    let end = process.hrtime( start );

    console.log( (( end[0] * 1000 + end[1] / 1e6 ) / CNT ).toFixed(2) + ' ms / hash' );
    console.log( ( CNT / ( end[0] + end[1] / 1e9 ) ).toFixed(0) + ' hash / s' );

    //console.log( t );
    //console.log( jwt.parse( t ));
}
/**/
