<?php
declare( strict_types = 1 );
// PHP oracle: computes the eleven contract lines with the ORIGINAL library.
require_once __DIR__ . '/../libs/func_verifyum_witness.php';

$dir = __DIR__ . '/vectors';
function load( string $dir, string $name ): array
{
    $raw = file_get_contents( $dir .'/'. $name );
    $v = json_decode( $raw, true, 512, JSON_THROW_ON_ERROR );
    if ( !is_array( $v ) ){ throw new RuntimeException( $name .' is not an object' ); }
    return $v;
}
$metadata = load( $dir, 'metadata.json' );
$bundle   = load( $dir, 'witnesses.json' );
$hourly   = load( $dir, 'hourly.json' );
$daily    = load( $dir, 'daily.json' );
$keys     = load( $dir, 'keys.json' );

$out = [];
$emit = function( string $k, string $v ) use ( &$out ){ $out[] = $k .'='. $v; };
$bool = fn( bool $b ): string => $b ? 'true' : 'false';

// R? proof leaf hash (validates metadata + signature inside the library)
$leaf = verifyum_witness_proof_leaf_hash( $metadata, $keys );
$emit( 'proof_leaf_hash', $leaf );

// Path walk with the library's node hash
$current = $leaf;
foreach ( $bundle['membership']['path'] as $step ){
    $current = $step['side'] === 'left'
        ? verifyum_witness_node_hash( $step['hash'], $current )
        : verifyum_witness_node_hash( $current, $step['hash'] );
}
$emit( 'path_root', $current );
$emit( 'path_matches_checkpoint', $bool(
    verifyum_witness_verify_path( $leaf, $bundle['membership']['path'], $bundle['checkpoint']['merkle_root'] )
) );

foreach ( [ 'hourly'=>$hourly, 'daily'=>$daily ] as $name=>$cp ){
    $h = verifyum_witness_checkpoint_hash( $cp );
    $emit( $name .'_checkpoint_hash', $h );
    $emit( $name .'_matches', $bool( hash_equals( $cp['checkpoint_hash'], $h ) ) );
}

$dd = verifyum_witness_checkpoint_document_digest( $daily );
$emit( 'daily_document_digest', $dd );
$emit( 'daily_sigsum_checksum', hash( 'sha256', verifyum_witness_digest_bytes( $dd ) ) );

// Independent signature check (the leaf hash already required it to pass)
$matching = null;
foreach ( $keys['keys'] as $key ){
    if ( $key['key_id'] === $metadata['service_signature']['key_id'] and $key['network'] === $metadata['anchor']['network'] ){
        $matching = $key;
    }
}
$pk = verifyum_service_base64url_decode( $matching['public_key'] );
$emit( 'service_signature_valid', $bool(
    verifyum_service_verify_metadata_signature( $metadata, $pk, $metadata['service_signature']['key_id'] )
) );

$probe = json_decode( '{"b":1,"a":"x<y&z/\u00e9","n":null,"t":true,"arr":[2,"s",{"z":0,"y":[]}]}', true, 512, JSON_THROW_ON_ERROR );
$emit( 'jcs_probe', verifyum_jcs_encode( $probe ) );

fwrite( STDOUT, implode( "\n", $out ) ."\n" );
fwrite( STDERR, "sodium=". ( extension_loaded( 'sodium' ) ? 'yes' : 'no' ) ."\n" );
