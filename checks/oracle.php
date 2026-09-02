<?php
declare( strict_types = 1 );

/*
 * The reference computing the eleven contract lines with the library that
 * runs in production. Every other port is compared against this output.
 *
 * Reads the vectors from VERIFYUM_VECTORS, falling back to the directory
 * beside this file, and exits non-zero when any recomputed value disagrees
 * with the published one. A check that cannot fail is not a check.
 */

require_once __DIR__ . '/../libs/func_verifyum_witness.php';

$dir = getenv( 'VERIFYUM_VECTORS' );
if ( !is_string( $dir ) or $dir === '' ){
    $dir = __DIR__ . '/vectors';
}

function load( string $dir, string $name ): array
{
    $raw = @file_get_contents( $dir .'/'. $name );
    if ( !is_string( $raw ) ){
        throw new RuntimeException( 'cannot read '. $name );
    }
    $value = json_decode( $raw, true, 512, JSON_THROW_ON_ERROR );
    if ( !is_array( $value ) ){
        throw new RuntimeException( $name .' is not an object' );
    }
    return $value;
}

try {
    $metadata = load( $dir, 'metadata.json' );
    $bundle   = load( $dir, 'witnesses.json' );
    $hourly   = load( $dir, 'hourly.json' );
    $daily    = load( $dir, 'daily.json' );
    $keys     = load( $dir, 'keys.json' );
} catch ( Throwable $error ){
    fwrite( STDERR, $error->getMessage() ."\n" );
    exit( 2 );
}

$out = [];
$emit = function ( string $key, string $value ) use ( &$out ): void {
    $out[] = $key .'='. $value;
};
$bool = fn ( bool $value ): string => $value ? 'true' : 'false';

// A document the reference rejects outright is a failed check, not a crash.
// Reporting it as a false line keeps the eleven-line contract intact.
$failed = false;
$attempt = function ( callable $work, $fallback ) use ( &$failed ) {
    try {
        return $work();
    } catch ( Throwable $error ){
        fwrite( STDERR, 'rejected by the reference: '. $error->getMessage() ."\n" );
        $failed = true;
        return $fallback;
    }
};

$zero = 'sha256:'. str_repeat( '0', 64 );

// R5. The library validates the metadata and its signature while hashing.
$leaf = $attempt( fn () => verifyum_witness_proof_leaf_hash( $metadata, $keys ), $zero );
$emit( 'proof_leaf_hash', $leaf );

$path = $bundle['membership']['path'] ?? [];
$current = $attempt( function () use ( $leaf, $path ) {
    $current = $leaf;
    foreach ( $path as $step ){
        $current = $step['side'] === 'left'
            ? verifyum_witness_node_hash( $step['hash'], $current )
            : verifyum_witness_node_hash( $current, $step['hash'] );
    }
    return $current;
}, $zero );
$emit( 'path_root', $current );

$root = (string)( $bundle['checkpoint']['merkle_root'] ?? '' );
$path_matches = $attempt( fn () => verifyum_witness_verify_path( $leaf, $path, $root ), false );
$emit( 'path_matches_checkpoint', $bool( $path_matches ) );

$checkpoint_matches = [];
foreach ( [ 'hourly'=>$hourly, 'daily'=>$daily ] as $name=>$checkpoint ){
    $hash = $attempt( fn () => verifyum_witness_checkpoint_hash( $checkpoint ), $zero );
    $emit( $name .'_checkpoint_hash', $hash );
    $matches = hash_equals( (string)( $checkpoint['checkpoint_hash'] ?? '' ), $hash );
    $checkpoint_matches[ $name ] = $matches;
    $emit( $name .'_matches', $bool( $matches ) );
}

$document_digest = $attempt( fn () => verifyum_witness_checkpoint_document_digest( $daily ), $zero );
$emit( 'daily_document_digest', $document_digest );
$emit( 'daily_sigsum_checksum', $attempt(
    fn () => hash( 'sha256', verifyum_witness_digest_bytes( $document_digest ) ),
    str_repeat( '0', 64 )
) );

// The leaf hash already required the signature to pass, but a reader running
// this alone should see the signature verdict on its own line.
$signature_valid = $attempt( function () use ( $metadata, $keys ) {
    $matching = null;
    foreach ( $keys['keys'] as $key ){
        if (
            $key['key_id'] === $metadata['service_signature']['key_id']
            and $key['network'] === $metadata['anchor']['network']
        ){
            $matching = $key;
        }
    }
    if ( $matching === null ){
        return false;
    }
    return verifyum_service_verify_metadata_signature(
        $metadata,
        verifyum_service_base64url_decode( $matching['public_key'] ),
        $metadata['service_signature']['key_id']
    );
}, false );
$emit( 'service_signature_valid', $bool( $signature_valid ) );

$probe = json_decode(
    '{"b":1,"a":"x<y&z/é","n":null,"t":true,"arr":[2,"s",{"z":0,"y":[]}]}',
    true,
    512,
    JSON_THROW_ON_ERROR
);
$emit( 'jcs_probe', verifyum_jcs_encode( $probe ) );

fwrite( STDOUT, implode( "\n", $out ) ."\n" );
fwrite( STDERR, 'sodium='. ( extension_loaded( 'sodium' ) ? 'yes' : 'no' ) ."\n" );

if (
    $failed
    or !$path_matches
    or !( $checkpoint_matches['hourly'] ?? false )
    or !( $checkpoint_matches['daily'] ?? false )
    or !$signature_valid
){
    exit( 1 );
}
exit( 0 );
