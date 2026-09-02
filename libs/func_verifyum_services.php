<?php
declare( strict_types = 1 );

/*
 * The four helpers the witness library needs from the Verifyum services
 * library. The full services library is operational code, signer, queue and
 * publisher adapters, and is not part of this repository. These functions
 * are copied verbatim from it.
 */

require_once __DIR__ .'/func_verifyum.php';

function verifyum_service_base64url_encode( string $bytes ): string
{
    return rtrim( strtr( base64_encode( $bytes ), '+/', '-_' ), '=' );
}

function verifyum_service_base64url_decode( string $encoded ): string
{
    if ( preg_match( '/\A[A-Za-z0-9_-]*\z/', $encoded ) !== 1 or strlen( $encoded ) % 4 === 1 ){
        throw new InvalidArgumentException( 'Invalid Base64url value' );
    }
    $padding = ( 4 - strlen( $encoded ) % 4 ) % 4;
    $decoded = base64_decode( strtr( $encoded, '-_', '+/' ) . str_repeat( '=', $padding ), true );
    if ( !is_string( $decoded ) or !hash_equals( $encoded, verifyum_service_base64url_encode( $decoded ) ) ){
        throw new InvalidArgumentException( 'Invalid Base64url value' );
    }
    return $decoded;
}

function verifyum_service_iso_time( int $timestamp ): string
{
    return gmdate( 'Y-m-d\TH:i:s\Z', $timestamp );
}

function verifyum_service_verify_metadata_signature(
    array $metadata,
    string $public_key,
    string $expected_key_id
): bool {
    if ( !extension_loaded( 'sodium' ) or strlen( $public_key ) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES ){
        return false;
    }
    $signature_record = $metadata['service_signature'] ?? null;
    if (
        !is_array( $signature_record )
        or array_is_list( $signature_record )
        or ( $signature_record['algorithm'] ?? null ) !== 'ed25519'
        or ( $signature_record['key_id'] ?? null ) !== $expected_key_id
        or !is_string( $signature_record['value'] ?? null )
    ){
        return false;
    }
    try {
        $signature = verifyum_service_base64url_decode( $signature_record['value'] );
    } catch ( InvalidArgumentException ){
        return false;
    }
    if ( strlen( $signature ) !== SODIUM_CRYPTO_SIGN_BYTES ){
        return false;
    }
    unset( $metadata['service_signature'] );
    try {
        $payload = verifyum_jcs_encode( $metadata );
    } catch ( Throwable ){
        return false;
    }
    return sodium_crypto_sign_verify_detached( $signature, $payload, $public_key );
}
