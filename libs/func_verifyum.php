<?php
declare( strict_types = 1 );

const VERIFYUM_PROOF_ID_PATTERN = '/\A[0-7][0-9a-hjkmnp-tv-z]{25}\z/';
const VERIFYUM_COMMITMENT_PATTERN = '/\Asha256:[0-9a-f]{64}\z/';
const VERIFYUM_MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const VERIFYUM_CROCKFORD_ALPHABET = '0123456789abcdefghjkmnpqrstvwxyz';

function verifyum_load_config( string $domain_dir ): array
{
    $defaults = [
        'network' => 'devnet',
        'anchor_enabled' => false,
        'anonymous_anchor_enabled' => false,
        'proof_store' => '/var/lib/verifyum/proofs',
        'metadata_socket' => '/run/verifyum/metadata.sock',
        'public_rpc_url' => 'https://api.devnet.solana.com',
        'anchor_address' => null,
        'anchor_credentials_path' => '/etc/verifyum/web/anchor-clients.json',
        'witness_checkpoint_store' => '/var/lib/verifyum/witness-outbox',
        'witness_membership_store' => '/var/lib/verifyum/witness-memberships',
        'witness_receipt_store' => '/var/lib/verifyum/witness-public-receipts',
        'announcement_store' => '/var/lib/verifyum/announcements',
        'm2m_log' => '/tmp/verifyum-m2m.log',
    ];

    $file = rtrim( $domain_dir, '/\\' ) .'/.verifyum-config.php';
    if ( !is_file( $file ) or !is_readable( $file ) ){
        return $defaults;
    }

    $configured = include $file;
    if ( !is_array( $configured ) ){
        return $defaults;
    }

    $config = array_merge( $defaults, $configured );
    if ( !in_array( $config['network'], [ 'devnet', 'mainnet-beta' ], true ) ){
        $config['network'] = 'devnet';
        $config['anchor_enabled'] = false;
        $config['anonymous_anchor_enabled'] = false;
    }

    $config['anchor_enabled'] = (bool)$config['anchor_enabled'];
    $config['anonymous_anchor_enabled'] = $config['anchor_enabled']
        and (bool)$config['anonymous_anchor_enabled'];
    return $config;
}

function verifyum_load_anchor_client_registry( string $path ): ?array
{
    clearstatcache( true, $path );
    if ( is_link( $path ) or !is_file( $path ) or !is_readable( $path ) ){
        return null;
    }
    if ( DIRECTORY_SEPARATOR === '/' ){
        $owner = fileowner( $path );
        $mode = fileperms( $path );
        if ( $owner !== 0 or !is_int( $mode ) or ( $mode & 0037 ) !== 0 ){
            return null;
        }
    }
    $size = filesize( $path );
    if ( $size === false or $size < 2 or $size > 65536 ){
        return null;
    }
    $raw = file_get_contents( $path );
    $registry = is_string( $raw ) ? json_decode( $raw, true ) : null;
    if (
        !is_array( $registry )
        or array_is_list( $registry )
        or array_diff( array_keys( $registry ), [ 'schema', 'updated_at', 'clients' ] ) !== []
        or ( $registry['schema'] ?? null ) !== 'verifyum-anchor-clients-v1'
        or !is_string( $registry['updated_at'] ?? null )
        or strtotime( $registry['updated_at'] ) === false
        or !is_array( $registry['clients'] ?? null )
        or !array_is_list( $registry['clients'] )
    ){
        return null;
    }

    $ids = [];
    $hashes = [];
    foreach ( $registry['clients'] as $client ){
        if (
            !is_array( $client )
            or array_is_list( $client )
            or array_diff( array_keys( $client ), [ 'id', 'token_sha256', 'status', 'created_at', 'updated_at' ] ) !== []
            or preg_match( '/\A[a-z0-9][a-z0-9._-]{0,63}\z/', (string)( $client['id'] ?? '' ) ) !== 1
            or preg_match( '/\A[0-9a-f]{64}\z/', (string)( $client['token_sha256'] ?? '' ) ) !== 1
            or !in_array( $client['status'] ?? null, [ 'active', 'revoked' ], true )
            or !is_string( $client['created_at'] ?? null )
            or strtotime( $client['created_at'] ) === false
            or !is_string( $client['updated_at'] ?? null )
            or strtotime( $client['updated_at'] ) === false
        ){
            return null;
        }
        $id = (string)$client['id'];
        $hash = (string)$client['token_sha256'];
        if ( isset( $ids[ $id ] ) or isset( $hashes[ $hash ] ) ){
            return null;
        }
        $ids[ $id ] = true;
        $hashes[ $hash ] = true;
    }
    return $registry;
}

function verifyum_authorize_anchor_client( string $registry_path, string $bearer_token ): ?string
{
    if (
        strlen( $bearer_token ) < 32
        or strlen( $bearer_token ) > 256
        or preg_match( '/\A[\x21-\x7e]+\z/', $bearer_token ) !== 1
    ){
        return null;
    }
    $registry = verifyum_load_anchor_client_registry( $registry_path );
    if ( $registry === null ){
        return null;
    }

    $presented_hash = hash( 'sha256', $bearer_token );
    $matched_id = null;
    foreach ( $registry['clients'] as $client ){
        $matches = hash_equals( (string)$client['token_sha256'], $presented_hash );
        if ( $matches and ( $client['status'] ?? null ) === 'active' ){
            $matched_id = (string)$client['id'];
        }
    }
    return $matched_id;
}

function verifyum_normalize_host( string $raw_host ): string
{
    $host = strtolower( trim( $raw_host ) );
    if ( preg_match( '/\A([^:]+):[0-9]+\z/', $host, $match ) ){
        $host = $match[1];
    }
    if ( !preg_match( '/\A[a-z0-9.-]{1,253}\z/', $host ) ){
        return '';
    }
    return trim( $host, '.' );
}

function verifyum_valid_proof_id( string $proof_id ): bool
{
    return preg_match( VERIFYUM_PROOF_ID_PATTERN, $proof_id ) === 1;
}

function verifyum_normalize_commitment( string $commitment ): ?string
{
    $commitment = trim( $commitment );
    return preg_match( VERIFYUM_COMMITMENT_PATTERN, $commitment ) === 1
        ? $commitment
        : null;
}

function verifyum_classify_host( string $host ): array
{
    if ( $host === 'verifyum.com' ){
        return [ 'kind'=>'base', 'proof_id'=>null, 'log_host'=>'verifyum.com' ];
    }
    if ( $host === 'www.verifyum.com' ){
        return [ 'kind'=>'www', 'proof_id'=>null, 'log_host'=>'verifyum.com' ];
    }
    if ( $host === 'api.verifyum.com' ){
        return [ 'kind'=>'api', 'proof_id'=>null, 'log_host'=>'api.verifyum.com' ];
    }
    if ( preg_match( '/\A([0-7][0-9a-hjkmnp-tv-z]{25})\.verifyum\.com\z/', $host, $match ) ){
        return [ 'kind'=>'proof', 'proof_id'=>$match[1], 'log_host'=>'proof.verifyum.com' ];
    }
    return [ 'kind'=>'invalid', 'proof_id'=>null, 'log_host'=>'invalid.verifyum.com' ];
}

function verifyum_generate_proof_id(): string
{
    $bytes = random_bytes( 16 );
    $buffer = 0;
    $bit_count = 2;
    $output = '';

    for ( $index = 0; $index < 16; $index++ ){
        $buffer = ( $buffer << 8 ) | ord( $bytes[ $index ] );
        $bit_count += 8;
        while ( $bit_count >= 5 ){
            $bit_count -= 5;
            $output .= VERIFYUM_CROCKFORD_ALPHABET[ ( $buffer >> $bit_count ) & 31 ];
            $buffer = $bit_count === 0 ? 0 : $buffer & ( ( 1 << $bit_count ) - 1 );
        }
    }

    if ( $bit_count !== 0 or strlen( $output ) !== 26 or !verifyum_valid_proof_id( $output ) ){
        throw new RuntimeException( 'Proof ID encoding failed' );
    }

    return $output;
}

function verifyum_build_memo( string $proof_id, string $commitment ): string
{
    if ( !verifyum_valid_proof_id( $proof_id ) ){
        throw new InvalidArgumentException( 'Invalid proof ID' );
    }
    $normalized = verifyum_normalize_commitment( $commitment );
    if ( $normalized === null ){
        throw new InvalidArgumentException( 'Invalid commitment' );
    }

    return 'verifyum:v2:id='. $proof_id .';alg=sha256;commitment='. substr( $normalized, 7 );
}

function verifyum_jcs_encode( mixed $value ): string
{
    if ( $value === null ){
        return 'null';
    }
    if ( is_bool( $value ) ){
        return $value ? 'true' : 'false';
    }
    if ( is_int( $value ) ){
        return (string)$value;
    }
    if ( is_float( $value ) ){
        if ( !is_finite( $value ) ){
            throw new InvalidArgumentException( 'Unsupported JCS number' );
        }
        throw new InvalidArgumentException( 'Floating-point values are not used by the Verifyum manifest' );
    }
    if ( is_string( $value ) ){
        $encoded = json_encode( $value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE );
        if ( $encoded === false ){
            throw new InvalidArgumentException( 'Invalid UTF-8 string in JCS input' );
        }
        return $encoded;
    }
    if ( !is_array( $value ) ){
        throw new InvalidArgumentException( 'Unsupported JCS value' );
    }

    if ( array_is_list( $value ) ){
        return '['. implode( ',', array_map( 'verifyum_jcs_encode', $value ) ) .']';
    }

    foreach ( array_keys( $value ) as $key ){
        if ( !is_string( $key ) or preg_match( '/\A[\x20-\x7e]+\z/', $key ) !== 1 ){
            throw new InvalidArgumentException( 'Verifyum manifest keys must be printable ASCII' );
        }
    }
    ksort( $value, SORT_STRING );
    $fields = [];
    foreach ( $value as $key=>$item ){
        $fields[] = verifyum_jcs_encode( $key ) .':'. verifyum_jcs_encode( $item );
    }
    return '{'. implode( ',', $fields ) .'}';
}

function verifyum_compute_commitment( array $manifest ): string
{
    $prefix = "verifyum:commitment:v2\n";
    return 'sha256:'. hash( 'sha256', $prefix . verifyum_jcs_encode( $manifest ) );
}

function verifyum_read_service_key_registry( string $proof_store ): ?array
{
    $path = rtrim( $proof_store, '/\\' ) .'/.verifyum-service-keys.json';
    if ( is_link( $path ) or !is_file( $path ) or !is_readable( $path ) ){
        return null;
    }
    $size = filesize( $path );
    if ( $size === false or $size < 2 or $size > 65536 ){
        return null;
    }
    $raw = file_get_contents( $path );
    $registry = is_string( $raw ) ? json_decode( $raw, true ) : null;
    if (
        !is_array( $registry )
        or array_is_list( $registry )
        or ( $registry['schema'] ?? null ) !== 'https://verifyum.com/schema/service-key-registry-v1.json'
        or !is_string( $registry['updated_at'] ?? null )
        or strtotime( $registry['updated_at'] ) === false
        or !is_array( $registry['keys'] ?? null )
        or !array_is_list( $registry['keys'] )
        or count( $registry['keys'] ) < 1
        or count( $registry['keys'] ) > 32
    ){
        return null;
    }

    $key_ids = [];
    $allowed = [ 'algorithm', 'key_id', 'network', 'public_key', 'status', 'created_at' ];
    foreach ( $registry['keys'] as $key ){
        if (
            !is_array( $key )
            or array_is_list( $key )
            or array_diff( array_keys( $key ), $allowed ) !== []
            or array_diff( $allowed, array_keys( $key ) ) !== []
            or ( $key['algorithm'] ?? null ) !== 'ed25519'
            or !is_string( $key['key_id'] ?? null )
            or preg_match( '/\A[A-Za-z0-9._-]{1,64}\z/', $key['key_id'] ) !== 1
            or !in_array( $key['network'] ?? null, [ 'devnet', 'mainnet-beta' ], true )
            or !is_string( $key['public_key'] ?? null )
            or preg_match( '/\A[A-Za-z0-9_-]{43}\z/', $key['public_key'] ) !== 1
            or !in_array( $key['status'] ?? null, [ 'active', 'retired' ], true )
            or !is_string( $key['created_at'] ?? null )
            or strtotime( $key['created_at'] ) === false
            or isset( $key_ids[ $key['key_id'] ] )
        ){
            return null;
        }
        $key_ids[ $key['key_id'] ] = true;
    }
    return $registry;
}
function verifyum_metadata_path( string $proof_store, string $proof_id ): ?string
{
    if ( !verifyum_valid_proof_id( $proof_id ) ){
        return null;
    }
    return rtrim( $proof_store, '/\\' ) .'/'. substr( $proof_id, 0, 2 ) .'/'. substr( $proof_id, 2, 2 ) .'/'. $proof_id .'.json';
}

function verifyum_read_public_metadata( string $proof_store, string $proof_id ): ?array
{
    $path = verifyum_metadata_path( $proof_store, $proof_id );
    if ( $path === null or !is_file( $path ) or !is_readable( $path ) ){
        return null;
    }

    $size = filesize( $path );
    if ( $size === false or $size < 2 or $size > 65536 ){
        return null;
    }

    $raw = file_get_contents( $path );
    if ( $raw === false ){
        return null;
    }
    $metadata = json_decode( $raw, true );
    if ( !is_array( $metadata ) or ( $metadata['proof_id'] ?? null ) !== $proof_id ){
        return null;
    }
    return $metadata;
}

function verifyum_metadata_request( string $socket_path, array $request, int $timeout_seconds = 2 ): array
{
    $error_number = 0;
    $error_message = '';
    $client = @stream_socket_client(
        'unix://'. $socket_path,
        $error_number,
        $error_message,
        $timeout_seconds,
        STREAM_CLIENT_CONNECT
    );
    if ( $client === false ){
        return [ 'ok'=>false, 'error'=>'metadata_service_unavailable' ];
    }

    stream_set_timeout( $client, $timeout_seconds );
    $payload = json_encode( $request, JSON_UNESCAPED_SLASHES );
    if ( $payload === false or strlen( $payload ) > 4096 ){
        fclose( $client );
        return [ 'ok'=>false, 'error'=>'invalid_internal_request' ];
    }

    $written = fwrite( $client, $payload ."\n" );
    if ( $written === false ){
        fclose( $client );
        return [ 'ok'=>false, 'error'=>'metadata_service_unavailable' ];
    }

    $line = fgets( $client, 16385 );
    fclose( $client );
    if ( $line === false or strlen( $line ) > 16384 ){
        return [ 'ok'=>false, 'error'=>'metadata_service_invalid_response' ];
    }

    $response = json_decode( $line, true );
    if ( !is_array( $response ) or !isset( $response['ok'] ) ){
        return [ 'ok'=>false, 'error'=>'metadata_service_invalid_response' ];
    }
    return $response;
}
