<?php
declare( strict_types = 1 );

require_once __DIR__ .'/func_verifyum_services.php';

const VERIFYUM_WITNESS_CHECKPOINT_SCHEMA = 'https://verifyum.com/schema/witness-checkpoint-v1.json';
const VERIFYUM_WITNESS_MEMBERSHIP_SCHEMA = 'https://verifyum.com/schema/witness-membership-v1.json';
const VERIFYUM_WITNESS_PROOF_MEMBERSHIP_SCHEMA = 'https://verifyum.com/schema/witness-proof-membership-v1.json';
const VERIFYUM_WITNESS_RECEIPT_SCHEMA = 'https://verifyum.com/schema/witness-channel-receipt-v1.json';
const VERIFYUM_WITNESS_MERKLE_ALGORITHM = 'verifyum-sha256-merkle-v1';

function verifyum_witness_digest( string $payload ): string
{
    return 'sha256:'. hash( 'sha256', $payload );
}

function verifyum_witness_valid_digest( mixed $digest ): bool
{
    return is_string( $digest ) and preg_match( '/\Asha256:[0-9a-f]{64}\z/', $digest ) === 1;
}

function verifyum_witness_digest_bytes( string $digest ): string
{
    if ( !verifyum_witness_valid_digest( $digest ) ){
        throw new InvalidArgumentException( 'The witness digest is invalid' );
    }
    $bytes = hex2bin( substr( $digest, 7 ) );
    if ( !is_string( $bytes ) or strlen( $bytes ) !== 32 ){
        throw new InvalidArgumentException( 'The witness digest is invalid' );
    }
    return $bytes;
}

function verifyum_witness_base32_lower( string $bytes ): string
{
    if ( $bytes === '' ){
        return '';
    }

    $alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    $encoded = '';
    $buffer = 0;
    $bits = 0;
    $length = strlen( $bytes );
    for ( $index = 0; $index < $length; $index++ ){
        $buffer = ( $buffer << 8 ) | ord( $bytes[$index] );
        $bits += 8;
        while ( $bits >= 5 ){
            $bits -= 5;
            $encoded .= $alphabet[( $buffer >> $bits ) & 31];
            $buffer &= ( 1 << $bits ) - 1;
        }
    }
    if ( $bits > 0 ){
        $encoded .= $alphabet[( $buffer << ( 5 - $bits ) ) & 31];
    }
    return $encoded;
}

function verifyum_witness_ct_hostname( array $daily_checkpoint ): string
{
    verifyum_witness_validate_checkpoint( $daily_checkpoint, 'daily' );
    $encoded_root = verifyum_witness_base32_lower(
        verifyum_witness_digest_bytes( $daily_checkpoint['merkle_root'] )
    );
    if ( strlen( $encoded_root ) !== 52 ){
        throw new RuntimeException( 'The daily witness root cannot form a CT hostname' );
    }
    return 'v1-'. $encoded_root .'.ct.verifyum.com';
}

function verifyum_witness_checkpoint_document( array $checkpoint ): string
{
    verifyum_witness_validate_checkpoint( $checkpoint );
    return verifyum_jcs_encode( $checkpoint ) ."\n";
}

function verifyum_witness_checkpoint_document_digest( array $checkpoint ): string
{
    return verifyum_witness_digest( verifyum_witness_checkpoint_document( $checkpoint ) );
}

function verifyum_witness_batch_id( array $checkpoint ): string
{
    verifyum_witness_validate_checkpoint( $checkpoint );
    $start = strtotime( $checkpoint['period_start'] );
    if ( !is_int( $start ) ){
        throw new InvalidArgumentException( 'The witness checkpoint start is invalid' );
    }
    return gmdate( 'Ymd\THis\Z', $start ) .'-'. substr( $checkpoint['checkpoint_hash'], 7 );
}

function verifyum_witness_public_checkpoint_url( array $checkpoint ): string
{
    verifyum_witness_validate_checkpoint( $checkpoint );
    return 'https://verifyum.com/witness/checkpoints/'. $checkpoint['kind'] .'/'
        . verifyum_witness_batch_id( $checkpoint ) .'.json';
}

function verifyum_witness_read_public_checkpoint(
    string $store,
    string $kind,
    string $batch_id
): ?array {
    if (
        !in_array( $kind, [ 'hourly', 'daily' ], true )
        or preg_match( '/\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{64}\z/', $batch_id ) !== 1
        or is_link( $store )
        or !is_dir( $store )
    ){
        return null;
    }
    $kind_directory = rtrim( $store, '/\\' ) .'/'. $kind;
    if ( is_link( $kind_directory ) or !is_dir( $kind_directory ) ){
        return null;
    }
    $path = $kind_directory .'/'. $batch_id .'.json';
    if ( is_link( $path ) or !is_file( $path ) or !is_readable( $path ) ){
        return null;
    }
    $size = filesize( $path );
    if ( !is_int( $size ) or $size < 2 or $size > 65536 ){
        return null;
    }
    $document = file_get_contents( $path );
    $checkpoint = is_string( $document ) ? json_decode( $document, true ) : null;
    if ( !is_array( $checkpoint ) ){
        return null;
    }
    try {
        verifyum_witness_validate_checkpoint( $checkpoint, $kind );
    } catch ( Throwable ){
        return null;
    }
    if (
        !hash_equals( verifyum_witness_batch_id( $checkpoint ), $batch_id )
        or !hash_equals( verifyum_witness_checkpoint_document( $checkpoint ), $document )
    ){
        return null;
    }
    return [ 'checkpoint'=>$checkpoint, 'document'=>$document ];
}

/**
 * Reads the published channel-receipt summary for one checkpoint. The
 * summary is a public mirror written by the publisher. It carries channel
 * states, artifact digests and non-secret provider references, never proof
 * members and never private material.
 */
function verifyum_witness_read_public_receipts(
    string $store,
    string $kind,
    string $batch_id
): ?array {
    if (
        !in_array( $kind, [ 'hourly', 'daily' ], true )
        or preg_match( '/\A[0-9]{8}T[0-9]{6}Z-[0-9a-f]{64}\z/', $batch_id ) !== 1
        or is_link( $store )
        or !is_dir( $store )
    ){
        return null;
    }
    $kind_directory = rtrim( $store, '/\\' ) .'/'. $kind;
    if ( is_link( $kind_directory ) or !is_dir( $kind_directory ) ){
        return null;
    }
    $path = $kind_directory .'/'. $batch_id .'.json';
    if ( is_link( $path ) or !is_file( $path ) or !is_readable( $path ) ){
        return null;
    }
    $size = filesize( $path );
    if ( !is_int( $size ) or $size < 2 or $size > 262144 ){
        return null;
    }
    $document = file_get_contents( $path );
    $summary = is_string( $document ) ? json_decode( $document, true ) : null;
    if (
        !is_array( $summary )
        or ( $summary['protocol'] ?? null ) !== 'verifyum'
        or ( $summary['version'] ?? null ) !== 1
        or !hash_equals( (string)( $summary['batch_id'] ?? '' ), $batch_id )
        or ( $summary['checkpoint_kind'] ?? null ) !== $kind
        or !is_array( $summary['channels'] ?? null )
    ){
        return null;
    }
    return [ 'summary'=>$summary, 'document'=>$document ];
}

function verifyum_witness_validate_public_proof_membership( array $bundle ): void
{
    if (
        !verifyum_witness_exact_fields(
            $bundle,
            [
                'schema',
                'protocol',
                'version',
                'network',
                'proof_id',
                'checkpoint_url',
                'checkpoint',
                'membership',
            ]
        )
        or $bundle['schema'] !== VERIFYUM_WITNESS_PROOF_MEMBERSHIP_SCHEMA
        or $bundle['protocol'] !== 'verifyum'
        or $bundle['version'] !== 1
        or !in_array( $bundle['network'], [ 'devnet', 'mainnet-beta' ], true )
        or !verifyum_valid_proof_id( $bundle['proof_id'] )
        or !is_string( $bundle['checkpoint_url'] )
        or !is_array( $bundle['checkpoint'] )
        or !is_array( $bundle['membership'] )
    ){
        throw new InvalidArgumentException( 'The public witness proof membership is invalid' );
    }
    verifyum_witness_validate_checkpoint( $bundle['checkpoint'], 'hourly' );
    verifyum_witness_validate_membership( $bundle['membership'], $bundle['checkpoint'] );
    if (
        $bundle['network'] !== $bundle['checkpoint']['network']
        or $bundle['checkpoint']['subject_type'] !== 'proof-v2'
        or $bundle['membership']['subject_type'] !== 'proof-v2'
        or $bundle['proof_id'] !== $bundle['membership']['subject_id']
        or !hash_equals(
            verifyum_witness_public_checkpoint_url( $bundle['checkpoint'] ),
            $bundle['checkpoint_url']
        )
    ){
        throw new InvalidArgumentException( 'The public witness proof membership is inconsistent' );
    }
}

function verifyum_witness_build_public_proof_membership(
    array $checkpoint,
    array $membership
): array {
    verifyum_witness_validate_checkpoint( $checkpoint, 'hourly' );
    verifyum_witness_validate_membership( $membership, $checkpoint );
    $bundle = [
        'schema'=>VERIFYUM_WITNESS_PROOF_MEMBERSHIP_SCHEMA,
        'protocol'=>'verifyum',
        'version'=>1,
        'network'=>$checkpoint['network'],
        'proof_id'=>$membership['subject_id'],
        'checkpoint_url'=>verifyum_witness_public_checkpoint_url( $checkpoint ),
        'checkpoint'=>$checkpoint,
        'membership'=>$membership,
    ];
    verifyum_witness_validate_public_proof_membership( $bundle );
    return $bundle;
}

function verifyum_witness_public_proof_membership_document( array $bundle ): string
{
    verifyum_witness_validate_public_proof_membership( $bundle );
    return verifyum_jcs_encode( $bundle ) ."\n";
}

function verifyum_witness_read_public_proof_membership(
    string $store,
    string $proof_id
): ?array {
    if ( !verifyum_valid_proof_id( $proof_id ) or is_link( $store ) or !is_dir( $store ) ){
        return null;
    }
    $first_shard = rtrim( $store, '/\\' ) .'/'. substr( $proof_id, 0, 2 );
    $second_shard = $first_shard .'/'. substr( $proof_id, 2, 2 );
    if (
        is_link( $first_shard )
        or !is_dir( $first_shard )
        or is_link( $second_shard )
        or !is_dir( $second_shard )
    ){
        return null;
    }
    $path = $second_shard .'/'. $proof_id .'.json';
    if ( is_link( $path ) or !is_file( $path ) or !is_readable( $path ) ){
        return null;
    }
    $size = filesize( $path );
    if ( !is_int( $size ) or $size < 2 or $size > 131072 ){
        return null;
    }
    $document = file_get_contents( $path );
    $bundle = is_string( $document ) ? json_decode( $document, true ) : null;
    if ( !is_array( $bundle ) ){
        return null;
    }
    try {
        verifyum_witness_validate_public_proof_membership( $bundle );
    } catch ( Throwable ){
        return null;
    }
    if (
        $bundle['proof_id'] !== $proof_id
        or !hash_equals( verifyum_witness_public_proof_membership_document( $bundle ), $document )
    ){
        return null;
    }
    return [ 'bundle'=>$bundle, 'document'=>$document ];
}

function verifyum_witness_sort_artifacts( array $artifacts ): array
{
    usort( $artifacts, static function ( array $left, array $right ): int {
        return strcmp( verifyum_jcs_encode( $left ), verifyum_jcs_encode( $right ) );
    } );
    return $artifacts;
}

/**
 * The checkpoint kind each channel witnesses, and by being the only such map,
 * the single definition of which channels exist. The three daily channels all
 * reach a free public service that an hourly cadence would abuse, and the
 * daily checkpoint already commits to every hourly one below it, so a daily
 * pass costs nothing in coverage.
 */
const VERIFYUM_WITNESS_CHANNEL_KINDS = [
    'opentimestamps'=>'hourly',
    'github'=>'hourly',
    'wayback'=>'hourly',
    'certificate-transparency'=>'daily',
    'eidas-timestamp'=>'daily',
    'software-heritage'=>'daily',
    'sigsum'=>'daily',
];

function verifyum_witness_channels(): array
{
    return array_keys( VERIFYUM_WITNESS_CHANNEL_KINDS );
}

function verifyum_witness_channel_checkpoint_kind( string $channel ): string
{
    if ( !isset( VERIFYUM_WITNESS_CHANNEL_KINDS[$channel] ) ){
        throw new InvalidArgumentException( 'The witness channel is invalid' );
    }
    return VERIFYUM_WITNESS_CHANNEL_KINDS[$channel];
}

function verifyum_witness_channel_subject_digest( array $checkpoint, string $channel ): string
{
    verifyum_witness_validate_checkpoint( $checkpoint );
    $expected_kind = verifyum_witness_channel_checkpoint_kind( $channel );
    if ( $checkpoint['kind'] !== $expected_kind ){
        throw new InvalidArgumentException(
            'The witness channel requires a '. $expected_kind .' checkpoint'
        );
    }
    // Certificate Transparency is the one channel whose subject is fixed by
    // an external format: the root has to survive as a DNS label.
    if ( $channel === 'certificate-transparency' ){
        return $checkpoint['merkle_root'];
    }
    return verifyum_witness_checkpoint_document_digest( $checkpoint );
}

function verifyum_witness_receipt_hash( array $receipt ): string
{
    unset( $receipt['receipt_hash'] );
    return verifyum_witness_digest(
        "verifyum:witness:channel-receipt:v1\n" . verifyum_jcs_encode( $receipt )
    );
}

function verifyum_witness_validate_channel_receipt( array $receipt, ?array $checkpoint = null ): void
{
    $fields = [
        'schema',
        'protocol',
        'version',
        'network',
        'checkpoint_kind',
        'checkpoint_hash',
        'channel',
        'state',
        'attempt',
        'observed_at',
        'subject_digest',
        'artifacts',
        'provider_reference',
        'reason',
        'previous_receipt_hash',
        'receipt_hash',
    ];
    if (
        !verifyum_witness_exact_fields( $receipt, $fields )
        or $receipt['schema'] !== VERIFYUM_WITNESS_RECEIPT_SCHEMA
        or $receipt['protocol'] !== 'verifyum'
        or $receipt['version'] !== 1
        or !in_array( $receipt['network'], [ 'devnet', 'mainnet-beta' ], true )
        or !in_array( $receipt['checkpoint_kind'], [ 'hourly', 'daily' ], true )
        or !verifyum_witness_valid_digest( $receipt['checkpoint_hash'] )
        or !in_array( $receipt['channel'], verifyum_witness_channels(), true )
        or !in_array( $receipt['state'], [ 'pending', 'confirmed', 'unavailable', 'failed' ], true )
        or !is_int( $receipt['attempt'] )
        or $receipt['attempt'] < 1
        or !verifyum_witness_canonical_time( $receipt['observed_at'] )
        or !verifyum_witness_valid_digest( $receipt['subject_digest'] )
        or !is_array( $receipt['artifacts'] )
        or !array_is_list( $receipt['artifacts'] )
        or count( $receipt['artifacts'] ) > 32
        or !( $receipt['provider_reference'] === null or (
            is_string( $receipt['provider_reference'] )
            and preg_match( '/\A[\x20-\x7e]{1,2048}\z/', $receipt['provider_reference'] ) === 1
        ) )
        or !( $receipt['reason'] === null or in_array(
            $receipt['reason'],
            [ 'pending-confirmation', 'provider-unavailable', 'provider-refused', 'invalid-response', 'local-error' ],
            true
        ) )
        or !( $receipt['previous_receipt_hash'] === null or verifyum_witness_valid_digest( $receipt['previous_receipt_hash'] ) )
        or !verifyum_witness_valid_digest( $receipt['receipt_hash'] )
    ){
        throw new InvalidArgumentException( 'The witness channel receipt is invalid' );
    }
    if (
        ( $receipt['attempt'] === 1 and $receipt['previous_receipt_hash'] !== null )
        or ( $receipt['attempt'] > 1 and $receipt['previous_receipt_hash'] === null )
    ){
        throw new InvalidArgumentException( 'The witness channel receipt chain is invalid' );
    }

    $artifact_kinds = [
        'opentimestamps-receipt',
        'github-commit',
        'wayback-capture',
        'x509-leaf-certificate',
        'x509-issuing-chain',
        'ct-signed-certificate-timestamp',
        'ct-inclusion-proof',
        'ct-signed-tree-head',
        'rfc3161-timestamp-token',
        'rfc3161-trust-chain',
        'software-heritage-snapshot',
        'sigsum-leaf',
        'sigsum-inclusion-proof',
        'sigsum-cosigned-tree-head',
        'sigsum-trust-policy',
    ];
    $artifact_ids = [];
    foreach ( $receipt['artifacts'] as $artifact ){
        if (
            !is_array( $artifact )
            or !verifyum_witness_exact_fields( $artifact, [ 'kind', 'digest', 'media_type', 'reference' ] )
            or !in_array( $artifact['kind'], $artifact_kinds, true )
            or !verifyum_witness_valid_digest( $artifact['digest'] )
            or !is_string( $artifact['media_type'] )
            or preg_match( '/\A[a-z0-9][a-z0-9.+-]*\/[a-z0-9][a-z0-9.+-]*\z/', $artifact['media_type'] ) !== 1
            or !( $artifact['reference'] === null or (
                is_string( $artifact['reference'] )
                and preg_match( '/\A[\x20-\x7e]{1,2048}\z/', $artifact['reference'] ) === 1
            ) )
        ){
            throw new InvalidArgumentException( 'A witness channel artifact is invalid' );
        }
        $artifact_id = verifyum_jcs_encode( $artifact );
        if ( isset( $artifact_ids[$artifact_id] ) ){
            throw new InvalidArgumentException( 'A witness channel artifact is duplicated' );
        }
        $artifact_ids[$artifact_id] = true;
    }
    if ( $receipt['artifacts'] !== verifyum_witness_sort_artifacts( $receipt['artifacts'] ) ){
        throw new InvalidArgumentException( 'Witness channel artifacts are not canonical' );
    }

    if (
        ( $receipt['state'] === 'confirmed' and $receipt['reason'] !== null )
        or ( $receipt['state'] === 'pending' and $receipt['reason'] !== 'pending-confirmation' )
        or ( $receipt['state'] === 'unavailable' and !in_array(
            $receipt['reason'],
            [ 'provider-unavailable', 'provider-refused' ],
            true
        ) )
        or ( $receipt['state'] === 'failed' and !in_array(
            $receipt['reason'],
            [ 'invalid-response', 'local-error' ],
            true
        ) )
    ){
        throw new InvalidArgumentException( 'The witness channel state is inconsistent' );
    }

    $kinds = array_column( $receipt['artifacts'], 'kind' );
    $required_confirmed = [
        'opentimestamps'=>[ 'opentimestamps-receipt' ],
        'github'=>[ 'github-commit' ],
        'wayback'=>[ 'wayback-capture' ],
        'certificate-transparency'=>[
            'x509-leaf-certificate',
            'x509-issuing-chain',
            'ct-signed-certificate-timestamp',
            'ct-inclusion-proof',
            'ct-signed-tree-head',
        ],
        // The token alone is not enough: a verifier in 2036 needs the issuing
        // chain and root that were current when the token was granted.
        'eidas-timestamp'=>[ 'rfc3161-timestamp-token', 'rfc3161-trust-chain' ],
        'software-heritage'=>[ 'software-heritage-snapshot' ],
        // The proof is only self-contained with the leaf itself, the path to
        // the root, the cosigned root, and the keys the verifier must trust.
        'sigsum'=>[ 'sigsum-leaf', 'sigsum-inclusion-proof', 'sigsum-cosigned-tree-head', 'sigsum-trust-policy' ],
    ];
    if ( $receipt['state'] === 'confirmed' ){
        foreach ( $required_confirmed[$receipt['channel']] as $required_kind ){
            if ( !in_array( $required_kind, $kinds, true ) ){
                throw new InvalidArgumentException( 'The confirmed witness evidence is incomplete' );
            }
        }
    }

    if ( !hash_equals( $receipt['receipt_hash'], verifyum_witness_receipt_hash( $receipt ) ) ){
        throw new InvalidArgumentException( 'The witness channel receipt hash is invalid' );
    }

    if ( $checkpoint !== null ){
        verifyum_witness_validate_checkpoint( $checkpoint );
        $expected_kind = verifyum_witness_channel_checkpoint_kind( $receipt['channel'] );
        $expected_subject = verifyum_witness_channel_subject_digest( $checkpoint, $receipt['channel'] );
        if (
            $receipt['network'] !== $checkpoint['network']
            or $receipt['checkpoint_kind'] !== $expected_kind
            or $checkpoint['kind'] !== $expected_kind
            or !hash_equals( $receipt['checkpoint_hash'], $checkpoint['checkpoint_hash'] )
            or !hash_equals( $receipt['subject_digest'], $expected_subject )
        ){
            throw new InvalidArgumentException( 'The witness receipt does not match its checkpoint' );
        }
    }
}

function verifyum_witness_build_channel_receipt(
    array $checkpoint,
    string $channel,
    string $state,
    string $observed_at,
    array $artifacts = [],
    ?string $provider_reference = null,
    ?string $reason = null,
    ?array $previous_receipt = null
): array {
    verifyum_witness_validate_checkpoint( $checkpoint );
    if ( $previous_receipt !== null ){
        verifyum_witness_validate_channel_receipt( $previous_receipt, $checkpoint );
        if (
            $previous_receipt['channel'] !== $channel
            or $previous_receipt['state'] === 'confirmed'
            or strcmp( $observed_at, $previous_receipt['observed_at'] ) < 0
        ){
            throw new InvalidArgumentException( 'The previous witness receipt cannot be extended' );
        }
    }
    $receipt = [
        'schema'=>VERIFYUM_WITNESS_RECEIPT_SCHEMA,
        'protocol'=>'verifyum',
        'version'=>1,
        'network'=>$checkpoint['network'],
        'checkpoint_kind'=>$checkpoint['kind'],
        'checkpoint_hash'=>$checkpoint['checkpoint_hash'],
        'channel'=>$channel,
        'state'=>$state,
        'attempt'=>$previous_receipt === null ? 1 : $previous_receipt['attempt'] + 1,
        'observed_at'=>$observed_at,
        'subject_digest'=>verifyum_witness_channel_subject_digest( $checkpoint, $channel ),
        'artifacts'=>verifyum_witness_sort_artifacts( $artifacts ),
        'provider_reference'=>$provider_reference,
        'reason'=>$reason,
        'previous_receipt_hash'=>$previous_receipt['receipt_hash'] ?? null,
    ];
    $receipt['receipt_hash'] = verifyum_witness_receipt_hash( $receipt );
    verifyum_witness_validate_channel_receipt( $receipt, $checkpoint );
    return $receipt;
}

function verifyum_witness_canonical_time( mixed $value ): bool
{
    if ( !is_string( $value ) or preg_match( '/\A[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\z/', $value ) !== 1 ){
        return false;
    }
    $timestamp = strtotime( $value );
    return is_int( $timestamp ) and verifyum_service_iso_time( $timestamp ) === $value;
}

function verifyum_witness_exact_fields( array $value, array $fields ): bool
{
    return !array_is_list( $value )
        and count( $value ) === count( $fields )
        and array_diff( array_keys( $value ), $fields ) === []
        and array_diff( $fields, array_keys( $value ) ) === [];
}

function verifyum_witness_validate_proof_metadata( array $metadata, array $key_registry ): void
{
    $fields = [
        'schema',
        'protocol',
        'version',
        'proof_id',
        'commitment',
        'submitted_at',
        'anchor',
        'service_signature',
    ];
    if (
        !verifyum_witness_exact_fields( $metadata, $fields )
        or $metadata['schema'] !== 'https://verifyum.com/schema/proof-v2.json'
        or $metadata['protocol'] !== 'verifyum'
        or $metadata['version'] !== 2
        or !is_string( $metadata['proof_id'] )
        or !verifyum_valid_proof_id( $metadata['proof_id'] )
        or !is_string( $metadata['commitment'] )
        or verifyum_normalize_commitment( $metadata['commitment'] ) !== $metadata['commitment']
        or !verifyum_witness_canonical_time( $metadata['submitted_at'] )
    ){
        throw new InvalidArgumentException( 'The public proof metadata is invalid' );
    }

    $anchor = $metadata['anchor'];
    $anchor_fields = [
        'provider',
        'network',
        'transaction_signature',
        'slot',
        'block_time',
        'anchor_address',
        'memo',
        'status',
    ];
    if (
        !is_array( $anchor )
        or !verifyum_witness_exact_fields( $anchor, $anchor_fields )
        or $anchor['provider'] !== 'solana'
        or !in_array( $anchor['network'], [ 'devnet', 'mainnet-beta' ], true )
        or !is_string( $anchor['transaction_signature'] )
        or preg_match( '/\A[1-9A-HJ-NP-Za-km-z]{80,90}\z/', $anchor['transaction_signature'] ) !== 1
        or !is_int( $anchor['slot'] )
        or $anchor['slot'] < 0
        or !( $anchor['block_time'] === null or verifyum_witness_canonical_time( $anchor['block_time'] ) )
        or !is_string( $anchor['anchor_address'] )
        or preg_match( '/\A[1-9A-HJ-NP-Za-km-z]{32,44}\z/', $anchor['anchor_address'] ) !== 1
        or !is_string( $anchor['memo'] )
        or !hash_equals( verifyum_build_memo( $metadata['proof_id'], $metadata['commitment'] ), $anchor['memo'] )
        or $anchor['status'] !== 'finalized'
    ){
        throw new InvalidArgumentException( 'The public proof anchor is invalid' );
    }

    $signature = $metadata['service_signature'];
    if (
        !is_array( $signature )
        or !verifyum_witness_exact_fields( $signature, [ 'algorithm', 'key_id', 'value' ] )
        or $signature['algorithm'] !== 'ed25519'
        or !is_string( $signature['key_id'] )
    ){
        throw new InvalidArgumentException( 'The public proof signature record is invalid' );
    }

    $matching_key = null;
    foreach ( $key_registry['keys'] ?? [] as $key ){
        if (
            is_array( $key )
            and ( $key['key_id'] ?? null ) === $signature['key_id']
            and ( $key['network'] ?? null ) === $anchor['network']
            and in_array( $key['status'] ?? null, [ 'active', 'retired' ], true )
            and ( $key['algorithm'] ?? null ) === 'ed25519'
            and is_string( $key['public_key'] ?? null )
        ){
            if ( $matching_key !== null ){
                throw new InvalidArgumentException( 'The verification key is not unique' );
            }
            $matching_key = $key;
        }
    }
    if ( $matching_key === null ){
        throw new InvalidArgumentException( 'The verification key is unavailable' );
    }

    try {
        $public_key = verifyum_service_base64url_decode( $matching_key['public_key'] );
    } catch ( InvalidArgumentException $exception ){
        throw new InvalidArgumentException( 'The verification key is invalid', 0, $exception );
    }
    if ( !verifyum_service_verify_metadata_signature( $metadata, $public_key, $signature['key_id'] ) ){
        throw new InvalidArgumentException( 'The public proof signature is invalid' );
    }
}

function verifyum_witness_proof_leaf_hash( array $metadata, array $key_registry ): string
{
    verifyum_witness_validate_proof_metadata( $metadata, $key_registry );
    return verifyum_witness_digest(
        "\x00verifyum:witness:proof-leaf:v1\n" . verifyum_jcs_encode( $metadata )
    );
}

function verifyum_witness_checkpoint_hash( array $checkpoint ): string
{
    unset( $checkpoint['checkpoint_hash'] );
    return verifyum_witness_digest(
        "verifyum:witness:checkpoint:v1\n" . verifyum_jcs_encode( $checkpoint )
    );
}

function verifyum_witness_validate_checkpoint( array $checkpoint, ?string $expected_kind = null ): void
{
    $fields = [
        'schema',
        'protocol',
        'version',
        'kind',
        'network',
        'period_start',
        'period_end',
        'created_at',
        'algorithm',
        'subject_type',
        'subject_count',
        'merkle_root',
        'previous_checkpoint_hash',
        'checkpoint_hash',
    ];
    if (
        !verifyum_witness_exact_fields( $checkpoint, $fields )
        or $checkpoint['schema'] !== VERIFYUM_WITNESS_CHECKPOINT_SCHEMA
        or $checkpoint['protocol'] !== 'verifyum'
        or $checkpoint['version'] !== 1
        or !in_array( $checkpoint['kind'], [ 'hourly', 'daily' ], true )
        or ( $expected_kind !== null and $checkpoint['kind'] !== $expected_kind )
        or !in_array( $checkpoint['network'], [ 'devnet', 'mainnet-beta' ], true )
        or !verifyum_witness_canonical_time( $checkpoint['period_start'] )
        or !verifyum_witness_canonical_time( $checkpoint['period_end'] )
        or !verifyum_witness_canonical_time( $checkpoint['created_at'] )
        or $checkpoint['algorithm'] !== VERIFYUM_WITNESS_MERKLE_ALGORITHM
        or !is_int( $checkpoint['subject_count'] )
        or $checkpoint['subject_count'] < 1
        or !verifyum_witness_valid_digest( $checkpoint['merkle_root'] )
        or !( $checkpoint['previous_checkpoint_hash'] === null or verifyum_witness_valid_digest( $checkpoint['previous_checkpoint_hash'] ) )
        or !verifyum_witness_valid_digest( $checkpoint['checkpoint_hash'] )
    ){
        throw new InvalidArgumentException( 'The witness checkpoint is invalid' );
    }
    $subject_type = $checkpoint['kind'] === 'hourly' ? 'proof-v2' : 'hourly-checkpoint-v1';
    if ( $checkpoint['subject_type'] !== $subject_type ){
        throw new InvalidArgumentException( 'The witness checkpoint subject type is invalid' );
    }

    $start = strtotime( $checkpoint['period_start'] );
    $end = strtotime( $checkpoint['period_end'] );
    $created = strtotime( $checkpoint['created_at'] );
    $duration = $checkpoint['kind'] === 'hourly' ? 3600 : 86400;
    if (
        !is_int( $start )
        or !is_int( $end )
        or !is_int( $created )
        or $start % $duration !== 0
        or $end - $start !== $duration
        or $created < $end
    ){
        throw new InvalidArgumentException( 'The witness checkpoint period is invalid' );
    }
    if ( !hash_equals( $checkpoint['checkpoint_hash'], verifyum_witness_checkpoint_hash( $checkpoint ) ) ){
        throw new InvalidArgumentException( 'The witness checkpoint hash is invalid' );
    }
}

function verifyum_witness_checkpoint_leaf_hash( array $checkpoint ): string
{
    verifyum_witness_validate_checkpoint( $checkpoint, 'hourly' );
    return verifyum_witness_digest(
        "\x00verifyum:witness:checkpoint-leaf:v1\n"
        . verifyum_witness_digest_bytes( $checkpoint['checkpoint_hash'] )
    );
}

function verifyum_witness_node_hash( string $left, string $right ): string
{
    return verifyum_witness_digest(
        "\x01verifyum:witness:node:v1\n"
        . verifyum_witness_digest_bytes( $left )
        . verifyum_witness_digest_bytes( $right )
    );
}

function verifyum_witness_merkle_tree( array $subjects ): array
{
    if ( $subjects === [] ){
        throw new InvalidArgumentException( 'An empty witness checkpoint is not allowed' );
    }
    usort( $subjects, static function ( array $left, array $right ): int {
        return strcmp( (string)( $left['id'] ?? '' ), (string)( $right['id'] ?? '' ) );
    } );

    $paths = [];
    $level = [];
    $previous_id = null;
    foreach ( $subjects as $subject ){
        $id = $subject['id'] ?? null;
        $leaf_hash = $subject['leaf_hash'] ?? null;
        if (
            !is_string( $id )
            or $id === ''
            or $id === $previous_id
            or !verifyum_witness_valid_digest( $leaf_hash )
        ){
            throw new InvalidArgumentException( 'The witness subject list is invalid' );
        }
        $previous_id = $id;
        $paths[ $id ] = [];
        $level[] = [ 'hash'=>$leaf_hash, 'members'=>[ $id ] ];
    }

    while ( count( $level ) > 1 ){
        $next_level = [];
        for ( $index = 0; $index < count( $level ); $index += 2 ){
            $left = $level[ $index ];
            $right = $level[ $index + 1 ] ?? null;
            if ( $right === null ){
                $next_level[] = $left;
                continue;
            }
            foreach ( $left['members'] as $member ){
                $paths[ $member ][] = [ 'side'=>'right', 'hash'=>$right['hash'] ];
            }
            foreach ( $right['members'] as $member ){
                $paths[ $member ][] = [ 'side'=>'left', 'hash'=>$left['hash'] ];
            }
            $next_level[] = [
                'hash'=>verifyum_witness_node_hash( $left['hash'], $right['hash'] ),
                'members'=>array_merge( $left['members'], $right['members'] ),
            ];
        }
        $level = $next_level;
    }

    return [
        'root'=>$level[0]['hash'],
        'subjects'=>$subjects,
        'paths'=>$paths,
    ];
}

function verifyum_witness_verify_path( string $leaf_hash, array $path, string $expected_root ): bool
{
    if ( !verifyum_witness_valid_digest( $leaf_hash ) or !verifyum_witness_valid_digest( $expected_root ) ){
        return false;
    }
    $current = $leaf_hash;
    foreach ( $path as $step ){
        if (
            !is_array( $step )
            or !verifyum_witness_exact_fields( $step, [ 'side', 'hash' ] )
            or !in_array( $step['side'], [ 'left', 'right' ], true )
            or !verifyum_witness_valid_digest( $step['hash'] )
        ){
            return false;
        }
        $current = $step['side'] === 'left'
            ? verifyum_witness_node_hash( $step['hash'], $current )
            : verifyum_witness_node_hash( $current, $step['hash'] );
    }
    return hash_equals( $expected_root, $current );
}

function verifyum_witness_validate_membership( array $membership, array $checkpoint ): void
{
    verifyum_witness_validate_checkpoint( $checkpoint );
    $fields = [
        'schema',
        'protocol',
        'version',
        'checkpoint_kind',
        'checkpoint_hash',
        'subject_type',
        'subject_id',
        'leaf_hash',
        'leaf_index',
        'leaf_count',
        'path',
    ];
    if (
        !verifyum_witness_exact_fields( $membership, $fields )
        or $membership['schema'] !== VERIFYUM_WITNESS_MEMBERSHIP_SCHEMA
        or $membership['protocol'] !== 'verifyum'
        or $membership['version'] !== 1
        or $membership['checkpoint_kind'] !== $checkpoint['kind']
        or !is_string( $membership['checkpoint_hash'] )
        or !hash_equals( $checkpoint['checkpoint_hash'], $membership['checkpoint_hash'] )
        or $membership['subject_type'] !== $checkpoint['subject_type']
        or !is_string( $membership['subject_id'] )
        or !verifyum_witness_valid_digest( $membership['leaf_hash'] )
        or !is_int( $membership['leaf_index'] )
        or $membership['leaf_index'] < 0
        or !is_int( $membership['leaf_count'] )
        or $membership['leaf_count'] !== $checkpoint['subject_count']
        or $membership['leaf_index'] >= $membership['leaf_count']
        or !is_array( $membership['path'] )
    ){
        throw new InvalidArgumentException( 'The witness membership is invalid' );
    }
    $valid_subject = $membership['subject_type'] === 'proof-v2'
        ? verifyum_valid_proof_id( $membership['subject_id'] )
        : verifyum_witness_valid_digest( $membership['subject_id'] );
    if (
        !$valid_subject
        or !verifyum_witness_verify_path(
            $membership['leaf_hash'],
            $membership['path'],
            $checkpoint['merkle_root']
        )
    ){
        throw new InvalidArgumentException( 'The witness membership proof is invalid' );
    }
}

function verifyum_witness_build_checkpoint(
    string $kind,
    string $network,
    string $period_start,
    string $period_end,
    string $created_at,
    ?string $previous_checkpoint_hash,
    array $subjects
): array {
    if ( !in_array( $kind, [ 'hourly', 'daily' ], true ) ){
        throw new InvalidArgumentException( 'The witness checkpoint kind is invalid' );
    }
    if ( !in_array( $network, [ 'devnet', 'mainnet-beta' ], true ) ){
        throw new InvalidArgumentException( 'The witness checkpoint network is invalid' );
    }
    if ( !( $previous_checkpoint_hash === null or verifyum_witness_valid_digest( $previous_checkpoint_hash ) ) ){
        throw new InvalidArgumentException( 'The previous witness checkpoint hash is invalid' );
    }

    $tree = verifyum_witness_merkle_tree( $subjects );
    $checkpoint = [
        'schema'=>VERIFYUM_WITNESS_CHECKPOINT_SCHEMA,
        'protocol'=>'verifyum',
        'version'=>1,
        'kind'=>$kind,
        'network'=>$network,
        'period_start'=>$period_start,
        'period_end'=>$period_end,
        'created_at'=>$created_at,
        'algorithm'=>VERIFYUM_WITNESS_MERKLE_ALGORITHM,
        'subject_type'=>$kind === 'hourly' ? 'proof-v2' : 'hourly-checkpoint-v1',
        'subject_count'=>count( $subjects ),
        'merkle_root'=>$tree['root'],
        'previous_checkpoint_hash'=>$previous_checkpoint_hash,
    ];
    $checkpoint['checkpoint_hash'] = verifyum_witness_checkpoint_hash( $checkpoint );
    verifyum_witness_validate_checkpoint( $checkpoint, $kind );

    $memberships = [];
    foreach ( $tree['subjects'] as $index=>$subject ){
        $id = $subject['id'];
        $memberships[ $id ] = [
            'schema'=>VERIFYUM_WITNESS_MEMBERSHIP_SCHEMA,
            'protocol'=>'verifyum',
            'version'=>1,
            'checkpoint_kind'=>$kind,
            'checkpoint_hash'=>$checkpoint['checkpoint_hash'],
            'subject_type'=>$checkpoint['subject_type'],
            'subject_id'=>$id,
            'leaf_hash'=>$subject['leaf_hash'],
            'leaf_index'=>$index,
            'leaf_count'=>count( $subjects ),
            'path'=>$tree['paths'][ $id ],
        ];
    }

    return [ 'checkpoint'=>$checkpoint, 'memberships'=>$memberships ];
}

function verifyum_witness_build_hourly_checkpoint(
    string $period_start,
    string $period_end,
    string $created_at,
    ?string $previous_checkpoint_hash,
    array $metadata_records,
    array $key_registry
): array {
    $network = null;
    $subjects = [];
    foreach ( $metadata_records as $metadata ){
        if ( !is_array( $metadata ) ){
            throw new InvalidArgumentException( 'The public proof record is invalid' );
        }
        verifyum_witness_validate_proof_metadata( $metadata, $key_registry );
        $record_network = $metadata['anchor']['network'];
        if ( $network !== null and $network !== $record_network ){
            throw new InvalidArgumentException( 'A checkpoint cannot mix networks' );
        }
        $network = $record_network;
        $subjects[] = [
            'id'=>$metadata['proof_id'],
            'leaf_hash'=>verifyum_witness_proof_leaf_hash( $metadata, $key_registry ),
        ];
    }
    if ( $network === null ){
        throw new InvalidArgumentException( 'An empty witness checkpoint is not allowed' );
    }
    return verifyum_witness_build_checkpoint(
        'hourly',
        $network,
        $period_start,
        $period_end,
        $created_at,
        $previous_checkpoint_hash,
        $subjects
    );
}

function verifyum_witness_build_daily_checkpoint(
    string $network,
    string $period_start,
    string $period_end,
    string $created_at,
    ?string $previous_checkpoint_hash,
    array $hourly_checkpoints
): array {
    if ( !verifyum_witness_canonical_time( $period_start ) or !verifyum_witness_canonical_time( $period_end ) ){
        throw new InvalidArgumentException( 'The daily checkpoint period is invalid' );
    }
    $daily_start = strtotime( $period_start );
    $daily_end = strtotime( $period_end );
    if ( !is_int( $daily_start ) or !is_int( $daily_end ) ){
        throw new InvalidArgumentException( 'The daily checkpoint period is invalid' );
    }

    usort( $hourly_checkpoints, static function ( mixed $left, mixed $right ): int {
        return strcmp(
            is_array( $left ) ? (string)( $left['period_start'] ?? '' ) : '',
            is_array( $right ) ? (string)( $right['period_start'] ?? '' ) : ''
        );
    } );
    $subjects = [];
    $previous_hourly = null;
    $hourly_periods = [];
    foreach ( $hourly_checkpoints as $checkpoint ){
        if ( !is_array( $checkpoint ) ){
            throw new InvalidArgumentException( 'The hourly witness checkpoint is invalid' );
        }
        verifyum_witness_validate_checkpoint( $checkpoint, 'hourly' );
        if ( $checkpoint['network'] !== $network ){
            throw new InvalidArgumentException( 'A daily checkpoint cannot mix networks' );
        }
        $hourly_start = strtotime( $checkpoint['period_start'] );
        $hourly_end = strtotime( $checkpoint['period_end'] );
        if (
            !is_int( $hourly_start )
            or !is_int( $hourly_end )
            or $hourly_start < $daily_start
            or $hourly_end > $daily_end
            or isset( $hourly_periods[ $checkpoint['period_start'] ] )
        ){
            throw new InvalidArgumentException( 'The hourly checkpoint is outside the daily period' );
        }
        if (
            $previous_hourly !== null
            and !hash_equals( $previous_hourly['checkpoint_hash'], (string)$checkpoint['previous_checkpoint_hash'] )
        ){
            throw new InvalidArgumentException( 'The hourly checkpoint chain is discontinuous' );
        }
        $hourly_periods[ $checkpoint['period_start'] ] = true;
        $previous_hourly = $checkpoint;
        $subjects[] = [
            'id'=>$checkpoint['checkpoint_hash'],
            'leaf_hash'=>verifyum_witness_checkpoint_leaf_hash( $checkpoint ),
        ];
    }
    return verifyum_witness_build_checkpoint(
        'daily',
        $network,
        $period_start,
        $period_end,
        $created_at,
        $previous_checkpoint_hash,
        $subjects
    );
}

/**
 * The seven external channels, in the order the witness page presents them,
 * and which tier each belongs to. A channel absent from this table is not
 * reported at all, so a future channel has to be classified deliberately
 * rather than appearing as an unlabelled row.
 */
const VERIFYUM_WITNESS_CHANNEL_TIERS = [
    'opentimestamps'           => [ 'tier'=>'independent', 'kind'=>'hourly' ],
    'eidas-timestamp'          => [ 'tier'=>'independent', 'kind'=>'daily' ],
    'sigsum'                   => [ 'tier'=>'independent', 'kind'=>'daily' ],
    'certificate-transparency' => [ 'tier'=>'independent', 'kind'=>'daily' ],
    'github'                   => [ 'tier'=>'operator',    'kind'=>'hourly' ],
    'wayback'                  => [ 'tier'=>'operator',    'kind'=>'hourly' ],
    'software-heritage'        => [ 'tier'=>'operator',    'kind'=>'daily' ],
];

const VERIFYUM_WITNESS_STATISTICS_MAX_BATCHES = 20000;

/**
 * Lists the batch ids present in one kind of a witness store, newest first.
 * Batch ids begin with a UTC timestamp, so a reverse sort is chronological
 * and no file has to be opened to order them.
 */
function verifyum_witness_list_batches( string $store, string $kind ): array
{
    if (
        !in_array( $kind, [ 'hourly', 'daily' ], true )
        or is_link( $store )
        or !is_dir( $store )
    ){
        return [];
    }
    $directory = rtrim( $store, '/\\' ) .'/'. $kind;
    if ( is_link( $directory ) or !is_dir( $directory ) ){
        return [];
    }
    $entries = @scandir( $directory );
    if ( !is_array( $entries ) ){
        return [];
    }
    $batches = [];
    foreach ( $entries as $entry ){
        if ( preg_match( '/\A([0-9]{8}T[0-9]{6}Z-[0-9a-f]{64})\.json\z/', $entry, $match ) !== 1 ){
            continue;
        }
        $batches[] = $match[1];
    }
    rsort( $batches, SORT_STRING );
    return array_slice( $batches, 0, VERIFYUM_WITNESS_STATISTICS_MAX_BATCHES );
}

/**
 * Whole minutes between two ISO 8601 instants, or null when either is
 * missing or unparseable. Used for the delay between a checkpoint being
 * made and a channel confirming it.
 */
function verifyum_witness_minutes_between( ?string $from, ?string $to ): ?int
{
    if ( !is_string( $from ) or !is_string( $to ) ){
        return null;
    }
    $start = strtotime( $from );
    $end = strtotime( $to );
    if ( $start === false or $end === false or $end < $start ){
        return null;
    }
    return (int)floor( ( $end - $start ) / 60 );
}

function verifyum_witness_median( array $values ): ?int
{
    if ( $values === [] ){
        return null;
    }
    sort( $values, SORT_NUMERIC );
    $middle = (int)floor( count( $values ) / 2 );
    if ( count( $values ) % 2 === 1 ){
        return (int)$values[ $middle ];
    }
    return (int)floor( ( $values[ $middle - 1 ] + $values[ $middle ] ) / 2 );
}

/**
 * Counts what the Witness Layer has actually done, from the same files the
 * public checkpoint and receipt endpoints serve. Nothing here reads a proof
 * or a membership, so the result can never carry a proof id: the figures
 * describe checkpoints and channels only.
 */
function verifyum_witness_public_statistics(
    string $checkpoint_store,
    string $receipt_store,
    string $network,
    ?int $now = null
): array {
    $now = $now ?? time();

    $channels = [];
    foreach ( VERIFYUM_WITNESS_CHANNEL_TIERS as $name=>$meta ){
        $channels[ $name ] = [
            'channel'=>$name,
            'tier'=>$meta['tier'],
            'checkpoint_kind'=>$meta['kind'],
            'confirmed'=>0,
            'pending'=>0,
            'unavailable'=>0,
            'failed'=>0,
            'latest_observed_at'=>null,
            'median_minutes_to_confirm'=>null,
        ];
    }
    $delays = [];

    $kinds = [];
    $proofs_in_checkpoints = 0;
    $earliest_period_start = null;
    $latest_period_end = null;

    foreach ( [ 'hourly', 'daily' ] as $kind ){
        $batches = verifyum_witness_list_batches( $checkpoint_store, $kind );
        $created = [];
        $latest = null;
        foreach ( $batches as $batch_id ){
            $checkpoint = verifyum_witness_read_public_checkpoint( $checkpoint_store, $kind, $batch_id );
            if ( $checkpoint === null ){
                continue;
            }
            $document = $checkpoint['checkpoint'] ?? $checkpoint['summary'] ?? null;
            if ( !is_array( $document ) ){
                continue;
            }
            if ( ( $document['network'] ?? null ) !== $network ){
                continue;
            }
            $created[ $batch_id ] = (string)( $document['created_at'] ?? '' );
            if ( $kind === 'hourly' ){
                $proofs_in_checkpoints += (int)( $document['subject_count'] ?? 0 );
            }
            $start = (string)( $document['period_start'] ?? '' );
            $end = (string)( $document['period_end'] ?? '' );
            if ( $start !== '' and ( $earliest_period_start === null or $start < $earliest_period_start ) ){
                $earliest_period_start = $start;
            }
            if ( $end !== '' and ( $latest_period_end === null or $end > $latest_period_end ) ){
                $latest_period_end = $end;
            }
            if ( $latest === null ){
                $latest = [
                    'batch_id'=>$batch_id,
                    'checkpoint_hash'=>(string)( $document['checkpoint_hash'] ?? '' ),
                    'created_at'=>(string)( $document['created_at'] ?? '' ),
                    'period_start'=>$start,
                    'period_end'=>$end,
                    'subject_count'=>(int)( $document['subject_count'] ?? 0 ),
                    'checkpoint_url'=>'https://verifyum.com/witness/checkpoints/'. $kind .'/'. $batch_id .'.json',
                    'receipt_url'=>'https://verifyum.com/witness/receipts/'. $kind .'/'. $batch_id .'.json',
                ];
            }
        }

        $kinds[ $kind ] = [
            'count'=>count( $created ),
            'latest'=>$latest,
        ];

        // Receipts advance after the checkpoint is written, so they are read
        // separately and joined on the batch id.
        foreach ( verifyum_witness_list_batches( $receipt_store, $kind ) as $batch_id ){
            $receipt = verifyum_witness_read_public_receipts( $receipt_store, $kind, $batch_id );
            if ( $receipt === null ){
                continue;
            }
            $summary = $receipt['summary'];
            if ( ( $summary['network'] ?? null ) !== $network ){
                continue;
            }
            foreach ( $summary['channels'] as $entry ){
                if ( !is_array( $entry ) ){
                    continue;
                }
                $name = (string)( $entry['channel'] ?? '' );
                $state = (string)( $entry['state'] ?? '' );
                if ( !isset( $channels[ $name ] ) or !isset( $channels[ $name ][ $state ] ) ){
                    continue;
                }
                $channels[ $name ][ $state ]++;
                $observed = is_string( $entry['observed_at'] ?? null ) ? $entry['observed_at'] : null;
                if ( $observed !== null and (
                    $channels[ $name ]['latest_observed_at'] === null
                    or $observed > $channels[ $name ]['latest_observed_at']
                ) ){
                    $channels[ $name ]['latest_observed_at'] = $observed;
                }
                if ( $state === 'confirmed' ){
                    $minutes = verifyum_witness_minutes_between( $created[ $batch_id ] ?? null, $observed );
                    if ( $minutes !== null ){
                        $delays[ $name ][] = $minutes;
                    }
                }
            }
        }
    }

    foreach ( $channels as $name=>$row ){
        $channels[ $name ]['median_minutes_to_confirm'] = verifyum_witness_median( $delays[ $name ] ?? [] );
    }

    $independent_confirmed = 0;
    $independent_total = 0;
    foreach ( $channels as $row ){
        if ( $row['tier'] !== 'independent' ){
            continue;
        }
        $independent_confirmed += $row['confirmed'];
        $independent_total += $row['confirmed'] + $row['pending'] + $row['unavailable'] + $row['failed'];
    }

    return [
        'schema'=>'https://verifyum.com/schema/witness-statistics-v1.json',
        'protocol'=>'verifyum',
        'version'=>1,
        'network'=>$network,
        'generated_at'=>verifyum_service_iso_time( $now ),
        'checkpoints'=>$kinds,
        'proofs_in_checkpoints'=>$proofs_in_checkpoints,
        'coverage'=>[
            'earliest_period_start'=>$earliest_period_start,
            'latest_period_end'=>$latest_period_end,
        ],
        'independent_confirmations'=>[
            'confirmed'=>$independent_confirmed,
            'total'=>$independent_total,
        ],
        'channels'=>array_values( $channels ),
    ];
}

/**
 * The statistics scan opens every checkpoint and receipt file, so the result
 * is cached briefly. The cache is written atomically and its age is checked
 * on every request, which means a stale file can never be served silently as
 * if it were current.
 */
function verifyum_witness_cached_statistics(
    string $checkpoint_store,
    string $receipt_store,
    string $network,
    string $cache_path,
    int $max_age_seconds = 300,
    ?int $now = null,
    ?string $range_key = null,
    ?string $log_directory = null,
    array $internal_addresses = VERIFYUM_ACTIVITY_INTERNAL_ADDRESSES
): array {
    $now = $now ?? time();
    if ( !is_link( $cache_path ) and is_file( $cache_path ) ){
        $stamped = @filemtime( $cache_path );
        if ( is_int( $stamped ) and ( $now - $stamped ) < $max_age_seconds ){
            $cached = @file_get_contents( $cache_path );
            $decoded = is_string( $cached ) ? json_decode( $cached, true ) : null;
            if ( is_array( $decoded ) and ( $decoded['protocol'] ?? null ) === 'verifyum' ){
                return $decoded;
            }
        }
    }

    $statistics = verifyum_witness_public_statistics(
        $checkpoint_store,
        $receipt_store,
        $network,
        $now
    );
    if ( $range_key !== null ){
        $statistics['range'] = verifyum_witness_statistics_series(
            $checkpoint_store,
            $receipt_store,
            $network,
            $range_key,
            $now
        );
        $statistics['recent'] = verifyum_witness_recent_checkpoints(
            $checkpoint_store,
            $receipt_store,
            $network
        );
        if ( $log_directory !== null ){
            $window = $statistics['range'];
            $statistics['activity'] = verifyum_activity_series(
                $log_directory,
                (int)strtotime( $window['from'] ),
                (int)strtotime( $window['to'] ),
                (int)$window['bucket_seconds'],
                VERIFYUM_ACTIVITY_HOSTS,
                $internal_addresses
            );
        }
    }

    $directory = dirname( $cache_path );
    if ( is_dir( $directory ) and is_writable( $directory ) ){
        $temporary = $directory .'/.'. basename( $cache_path ) .'.tmp-'. bin2hex( random_bytes( 6 ) );
        $encoded = json_encode( $statistics, JSON_UNESCAPED_SLASHES );
        if ( is_string( $encoded ) and file_put_contents( $temporary, $encoded ) === strlen( $encoded ) ){
            @chmod( $temporary, 0644 );
            if ( !@rename( $temporary, $cache_path ) ){
                @unlink( $temporary );
            }
        } else {
            @unlink( $temporary );
        }
    }

    return $statistics;
}

/**
 * The ranges the status page offers, with the bucket each is drawn at. A
 * range is chosen so it lands between roughly twelve and fifty two buckets:
 * enough to show a shape, few enough to stay readable.
 */
const VERIFYUM_WITNESS_STATISTICS_RANGES = [
    '1h'  => [ 'seconds'=>3600,     'bucket'=>300,    'label'=>'last hour' ],
    '6h'  => [ 'seconds'=>21600,    'bucket'=>1800,   'label'=>'last 6 hours' ],
    '12h' => [ 'seconds'=>43200,    'bucket'=>3600,   'label'=>'last 12 hours' ],
    '24h' => [ 'seconds'=>86400,    'bucket'=>3600,   'label'=>'last 24 hours' ],
    '7d'  => [ 'seconds'=>604800,   'bucket'=>21600,  'label'=>'last week' ],
    '30d' => [ 'seconds'=>2592000,  'bucket'=>86400,  'label'=>'last month' ],
    '1y'  => [ 'seconds'=>31536000, 'bucket'=>604800, 'label'=>'last year' ],
];

const VERIFYUM_WITNESS_STATISTICS_DEFAULT_RANGE = '7d';

/**
 * The instant a batch id refers to. Batch ids begin with the period start in
 * basic ISO 8601, so a range can be applied without opening the file, which
 * is what keeps a year long range from reading every checkpoint on disk.
 */
function verifyum_witness_batch_time( string $batch_id ): ?int
{
    if ( preg_match( '/\A([0-9]{4})([0-9]{2})([0-9]{2})T([0-9]{2})([0-9]{2})([0-9]{2})Z-[0-9a-f]{64}\z/', $batch_id, $match ) !== 1 ){
        return null;
    }
    $stamp = gmmktime(
        (int)$match[4],
        (int)$match[5],
        (int)$match[6],
        (int)$match[2],
        (int)$match[3],
        (int)$match[1]
    );
    return $stamp === false ? null : $stamp;
}

/**
 * Counts the layer's activity over one window, bucketed for drawing. The
 * figures are the same ones the totals are built from, restricted to a
 * period, so a chart can never show something the totals contradict.
 */
function verifyum_witness_statistics_series(
    string $checkpoint_store,
    string $receipt_store,
    string $network,
    string $range_key,
    ?int $now = null
): array {
    $now = $now ?? time();
    if ( !isset( VERIFYUM_WITNESS_STATISTICS_RANGES[ $range_key ] ) ){
        $range_key = VERIFYUM_WITNESS_STATISTICS_DEFAULT_RANGE;
    }
    $range = VERIFYUM_WITNESS_STATISTICS_RANGES[ $range_key ];
    $bucket = $range['bucket'];

    // Buckets are aligned to the bucket size rather than to the current
    // second, so the same request a minute later draws the same bars. The
    // window ends at the last completed bucket, so a bar is never drawn
    // short merely because its period is still running.
    $end = (int)( floor( $now / $bucket ) * $bucket );
    $start = $end - $range['seconds'];
    $count = (int)( $range['seconds'] / $bucket );

    $labels = [];
    for ( $index = 0; $index < $count; $index++ ){
        $labels[] = verifyum_service_iso_time( $start + ( $index * $bucket ) );
    }

    $zeros = array_fill( 0, $count, 0 );
    $series = [
        'checkpoints_hourly'=>$zeros,
        'checkpoints_daily'=>$zeros,
        'proofs'=>$zeros,
    ];
    $channel_series = [];
    foreach ( VERIFYUM_WITNESS_CHANNEL_TIERS as $name=>$meta ){
        $channel_series[ $name ] = [
            'confirmed'=>$zeros,
            'waiting'=>$zeros,
            'failed'=>$zeros,
            'median_minutes'=>array_fill( 0, $count, null ),
        ];
    }
    $delays = [];

    $slot = static function ( int $stamp ) use ( $start, $bucket, $count ): ?int {
        $index = (int)floor( ( $stamp - $start ) / $bucket );
        return ( $index >= 0 and $index < $count ) ? $index : null;
    };

    foreach ( [ 'hourly', 'daily' ] as $kind ){
        $created = [];
        foreach ( verifyum_witness_list_batches( $checkpoint_store, $kind ) as $batch_id ){
            $stamp = verifyum_witness_batch_time( $batch_id );
            if ( $stamp === null or $stamp < $start or $stamp >= $end ){
                continue;
            }
            $checkpoint = verifyum_witness_read_public_checkpoint( $checkpoint_store, $kind, $batch_id );
            if ( $checkpoint === null ){
                continue;
            }
            $document = $checkpoint['checkpoint'];
            if ( ( $document['network'] ?? null ) !== $network ){
                continue;
            }
            $index = $slot( $stamp );
            if ( $index === null ){
                continue;
            }
            $created[ $batch_id ] = (string)( $document['created_at'] ?? '' );
            $series[ 'checkpoints_'. $kind ][ $index ]++;
            if ( $kind === 'hourly' ){
                $series['proofs'][ $index ] += (int)( $document['subject_count'] ?? 0 );
            }
        }

        foreach ( verifyum_witness_list_batches( $receipt_store, $kind ) as $batch_id ){
            $stamp = verifyum_witness_batch_time( $batch_id );
            if ( $stamp === null or $stamp < $start or $stamp >= $end ){
                continue;
            }
            $index = $slot( $stamp );
            if ( $index === null ){
                continue;
            }
            $receipt = verifyum_witness_read_public_receipts( $receipt_store, $kind, $batch_id );
            if ( $receipt === null or ( $receipt['summary']['network'] ?? null ) !== $network ){
                continue;
            }
            foreach ( $receipt['summary']['channels'] as $entry ){
                if ( !is_array( $entry ) ){
                    continue;
                }
                $name = (string)( $entry['channel'] ?? '' );
                if ( !isset( $channel_series[ $name ] ) ){
                    continue;
                }
                $state = (string)( $entry['state'] ?? '' );
                if ( $state === 'confirmed' ){
                    $channel_series[ $name ]['confirmed'][ $index ]++;
                    $minutes = verifyum_witness_minutes_between(
                        $created[ $batch_id ] ?? null,
                        is_string( $entry['observed_at'] ?? null ) ? $entry['observed_at'] : null
                    );
                    if ( $minutes !== null ){
                        $delays[ $name ][ $index ][] = $minutes;
                    }
                } elseif ( $state === 'failed' ){
                    $channel_series[ $name ]['failed'][ $index ]++;
                } elseif ( $state === 'pending' or $state === 'unavailable' ){
                    $channel_series[ $name ]['waiting'][ $index ]++;
                }
            }
        }
    }

    foreach ( $delays as $name=>$buckets ){
        foreach ( $buckets as $index=>$values ){
            $channel_series[ $name ]['median_minutes'][ $index ] = verifyum_witness_median( $values );
        }
    }

    return [
        'key'=>$range_key,
        'label'=>$range['label'],
        'from'=>verifyum_service_iso_time( $start ),
        'to'=>verifyum_service_iso_time( $end ),
        'bucket_seconds'=>$bucket,
        'buckets'=>$labels,
        'series'=>$series,
        'channels'=>$channel_series,
    ];
}

const VERIFYUM_WITNESS_RECENT_LIMIT = 25;

/**
 * The newest checkpoints of each kind with the outbound references their
 * receipts carry, so a reader can leave for the provider and check the
 * record where it actually lives. Only http and https references travel:
 * anything else is a local artifact digest, not somewhere to send a reader.
 */
function verifyum_witness_recent_checkpoints(
    string $checkpoint_store,
    string $receipt_store,
    string $network,
    int $limit = VERIFYUM_WITNESS_RECENT_LIMIT
): array {
    $recent = [];
    foreach ( [ 'hourly', 'daily' ] as $kind ){
        $taken = 0;
        foreach ( verifyum_witness_list_batches( $checkpoint_store, $kind ) as $batch_id ){
            if ( $taken >= $limit ){
                break;
            }
            $checkpoint = verifyum_witness_read_public_checkpoint( $checkpoint_store, $kind, $batch_id );
            if ( $checkpoint === null ){
                continue;
            }
            $document = $checkpoint['checkpoint'];
            if ( ( $document['network'] ?? null ) !== $network ){
                continue;
            }
            $taken++;

            $channels = [];
            $receipt = verifyum_witness_read_public_receipts( $receipt_store, $kind, $batch_id );
            if ( $receipt !== null and ( $receipt['summary']['network'] ?? null ) === $network ){
                foreach ( $receipt['summary']['channels'] as $entry ){
                    if ( !is_array( $entry ) ){
                        continue;
                    }
                    $name = (string)( $entry['channel'] ?? '' );
                    if ( !isset( VERIFYUM_WITNESS_CHANNEL_TIERS[ $name ] ) ){
                        continue;
                    }
                    $links = [];
                    foreach ( (array)( $entry['artifacts'] ?? [] ) as $artifact ){
                        if ( !is_array( $artifact ) ){
                            continue;
                        }
                        $reference = $artifact['reference'] ?? null;
                        if ( !is_string( $reference ) or preg_match( '#\Ahttps?://#i', $reference ) !== 1 ){
                            continue;
                        }
                        $links[] = [
                            'kind'=>(string)( $artifact['kind'] ?? 'artifact' ),
                            'url'=>$reference,
                        ];
                    }
                    $channels[] = [
                        'channel'=>$name,
                        'tier'=>VERIFYUM_WITNESS_CHANNEL_TIERS[ $name ]['tier'],
                        'state'=>(string)( $entry['state'] ?? '' ),
                        'observed_at'=>is_string( $entry['observed_at'] ?? null ) ? $entry['observed_at'] : null,
                        'links'=>$links,
                    ];
                }
            }

            $recent[] = [
                'kind'=>$kind,
                'batch_id'=>$batch_id,
                'period_start'=>(string)( $document['period_start'] ?? '' ),
                'period_end'=>(string)( $document['period_end'] ?? '' ),
                'created_at'=>(string)( $document['created_at'] ?? '' ),
                'subject_count'=>(int)( $document['subject_count'] ?? 0 ),
                'merkle_root'=>(string)( $document['merkle_root'] ?? '' ),
                'checkpoint_url'=>'https://verifyum.com/witness/checkpoints/'. $kind .'/'. $batch_id .'.json',
                'receipt_url'=>'https://verifyum.com/witness/receipts/'. $kind .'/'. $batch_id .'.json',
                'channels'=>$channels,
            ];
        }
    }

    // Newest first across both kinds, so the list reads as one history.
    usort( $recent, static function ( array $left, array $right ): int {
        return strcmp( (string)$right['period_start'], (string)$left['period_start'] );
    } );
    return $recent;
}

/*
 * Site activity is counted from the access log the server already writes and
 * the privacy page already describes. Nothing new is collected and nothing
 * runs in a visitor's browser. Addresses are used to count how many distinct
 * sources appeared and are never stored or returned: they are hashed into a
 * set that is discarded when the count is taken.
 *
 * The log is daily files under a temporary directory with a thirty day
 * policy, so a window reaching further back than that is answered from what
 * survives, and the result says how far the log actually goes.
 */

const VERIFYUM_ACTIVITY_LOG_DIR = '/tmp';
// The log directory is shared with other applications on this host that use
// the same naming, so the hosts are listed rather than discovered. Counting
// a neighbour's traffic as ours would be worse than counting none.
const VERIFYUM_ACTIVITY_HOSTS = [
    'verifyum.com',
    'api.verifyum.com',
    'proof.verifyum.com',
    'invalid.verifyum.com',
];
const VERIFYUM_ACTIVITY_MAX_LINES = 400000;
const VERIFYUM_ACTIVITY_TOP_PATHS = 12;

/*
 * Traffic that is ours, and traffic that was never going to be a visitor.
 *
 * The addresses are configured rather than guessed: the operator knows which
 * are theirs and nothing in the log says so. Loopback is the default because
 * a request from the machine itself is always the machine itself.
 *
 * A probe is a request for something this service has never served. The list
 * is of what scanners actually ask for, not of what we route, so adding a
 * page later cannot turn it into a probe by accident.
 */
const VERIFYUM_ACTIVITY_INTERNAL_ADDRESSES = [ '127.0.0.1', '::1' ];
const VERIFYUM_ACTIVITY_PROBE_PATTERN =
    '#\\A/(\\.git|\\.env|\\.aws|\\.ssh|\\.vscode|\\.idea|\\.DS_Store'
    .'|wp-|wordpress|xmlrpc\\.php|wp-login|wp-admin'
    .'|phpmyadmin|pma/|myadmin|adminer'
    .'|cgi-bin|vendor/|config\\.json|configuration\\.php'
    .'|\\.svn|\\.hg|backup|dump\\.sql|shell\\.php|eval-stdin)#i';

function verifyum_activity_is_internal( string $address, array $internal ): bool
{
    foreach ( $internal as $known ){
        if ( $address === $known ){
            return true;
        }
    }
    return false;
}

/**
 * Whether a path is one only a scanner asks for. A request nobody could have
 * followed a link to is not a visitor, and counting it as one flatters every
 * figure beside it.
 */
function verifyum_activity_is_probe( string $path ): bool
{
    return preg_match( VERIFYUM_ACTIVITY_PROBE_PATTERN, $path ) === 1;
}

/**
 * Which part of the service a request was for. The page a visitor reads, a
 * proof someone was given, the machine surface, or the files a page pulls in
 * on its own. Assets are separated because one page view drags several with
 * it and would otherwise drown the count it belongs to.
 */
function verifyum_activity_area( string $host, string $path ): string
{
    if ( $host === 'proof.verifyum.com' ){
        return 'proof';
    }
    if ( $host === 'api.verifyum.com' ){
        return 'api';
    }
    // A request that named no host we serve is almost always a scanner, and
    // counting it as a page view would flatter every other figure.
    if ( $host === 'invalid.verifyum.com' ){
        return 'unknown_host';
    }
    if ( preg_match( '#\A/(assets|imgs)/#', $path ) === 1
        or preg_match( '#\.(css|js|mjs|png|jpg|jpeg|svg|ico|woff2?|map)\z#i', $path ) === 1 ){
        return 'asset';
    }
    if ( preg_match( '#\A/(witness|api)/#', $path ) === 1 ){
        return 'record';
    }
    return 'page';
}

/**
 * Whether the user agent announces itself as an automated client. This is
 * what the client says about itself and nothing more, so the figure is a
 * floor for automated traffic, never a measurement of it.
 */
function verifyum_activity_is_declared_bot( string $user_agent ): bool
{
    return preg_match(
        '/bot|crawler|spider|slurp|curl|wget|python-requests|httpx|scrapy|headless|monitor|uptime|probe|scanner/i',
        $user_agent
    ) === 1;
}

/**
 * The earliest date the log still holds, taken from the file names rather
 * than from their contents. A quiet day is not a missing day, and the
 * distinction decides whether the page may claim to cover a window.
 */
function verifyum_activity_log_reach( string $directory, array $hosts = VERIFYUM_ACTIVITY_HOSTS ): ?int
{
    if ( is_link( $directory ) or !is_dir( $directory ) ){
        return null;
    }
    $entries = @scandir( $directory );
    if ( !is_array( $entries ) ){
        return null;
    }
    $earliest = null;
    foreach ( $entries as $entry ){
        if ( preg_match( '/\Aswoole_access_(\d{4}-\d{2}-\d{2})-\[(.+)\]\.log\z/', $entry, $match ) !== 1 ){
            continue;
        }
        // A neighbour application writing beside us must not decide how far
        // our own log reaches.
        if ( !in_array( $match[2], $hosts, true ) ){
            continue;
        }
        // Read in the writer's timezone, for the same reason.
        $day = strtotime( $match[1] .' 00:00:00' );
        if ( $day !== false and ( $earliest === null or $day < $earliest ) ){
            $earliest = $day;
        }
    }
    return $earliest;
}

function verifyum_activity_log_files( string $directory, int $from, int $to, array $hosts ): array
{
    if ( is_link( $directory ) or !is_dir( $directory ) ){
        return [];
    }
    $files = [];
    // The server names each file and stamps each line with date(), meaning
    // its own timezone, so the same function has to be used to find them.
    // A day either side is opened anyway and the per line timestamp decides.
    for ( $day = $from - 86400; $day <= $to + 86400; $day += 86400 ){
        foreach ( $hosts as $host ){
            $path = rtrim( $directory, '/\\' ) .'/swoole_access_'. date( 'Y-m-d', $day ) .'-['. $host .'].log';
            if ( !is_link( $path ) and is_file( $path ) and is_readable( $path ) ){
                $files[ $path ] = $host;
            }
        }
    }
    return $files;
}

/**
 * Counts requests, distinct sources and areas per bucket over one window.
 * The return carries no address, no user agent and no full request line: a
 * count, a set size, and the paths that were asked for most.
 */
function verifyum_activity_series(
    string $log_directory,
    int $from,
    int $to,
    int $bucket,
    array $hosts = VERIFYUM_ACTIVITY_HOSTS,
    array $internal = VERIFYUM_ACTIVITY_INTERNAL_ADDRESSES
): array {
    $count = max( 1, (int)( ( $to - $from ) / $bucket ) );
    $zeros = array_fill( 0, $count, 0 );
    $areas = [
        'page'=>$zeros,
        'proof'=>$zeros,
        'api'=>$zeros,
        'record'=>$zeros,
        'asset'=>$zeros,
        'unknown_host'=>$zeros,
    ];
    $requests = $zeros;
    $declared_bots = $zeros;
    $internal_requests = $zeros;
    $probe_requests = $zeros;
    $outside_requests = $zeros;
    $sources = array_fill( 0, $count, [] );
    $paths = [];
    $lines_read = 0;
    $truncated = false;

    foreach ( verifyum_activity_log_files( $log_directory, $from, $to, $hosts ) as $path=>$host ){
        $handle = @fopen( $path, 'rb' );
        if ( $handle === false ){
            continue;
        }
        while ( ( $line = fgets( $handle ) ) !== false ){
            if ( ++$lines_read > VERIFYUM_ACTIVITY_MAX_LINES ){
                $truncated = true;
                break 2;
            }
            if ( preg_match(
                '/\A\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\] (\S+) "(\S+) ([^"]*)" "[^"]*" "(.*)"\s*\z/',
                $line,
                $match
            ) !== 1 ){
                continue;
            }
            $stamp = strtotime( $match[1] );
            if ( $stamp === false ){
                continue;
            }
            if ( $stamp < $from or $stamp >= $to ){
                continue;
            }
            $index = (int)floor( ( $stamp - $from ) / $bucket );
            if ( $index < 0 or $index >= $count ){
                continue;
            }

            $requests[ $index ]++;
            // Each request is counted once, in the first category it falls
            // into, so the four always add up to the total. Overlapping
            // counters made an earlier version subtract our own health check
            // twice, because it is ours and calls itself curl.
            $is_internal = verifyum_activity_is_internal( $match[2], $internal );
            // && rather than and: the latter binds weaker than assignment,
            // so $x = A and B() assigns A and discards B, which is exactly
            // what happened here and made almost everything a probe.
            $is_probe = !$is_internal && verifyum_activity_is_probe( $match[4] );
            $is_crawler = !$is_internal && !$is_probe
                && verifyum_activity_is_declared_bot( $match[5] );
            if ( $is_internal ){
                $internal_requests[ $index ]++;
            } elseif ( $is_probe ){
                $probe_requests[ $index ]++;
            } elseif ( $is_crawler ){
                $declared_bots[ $index ]++;
            } else {
                $outside_requests[ $index ]++;
            }
            // Only the presence of a source matters, so the address is
            // reduced to a short digest and the digest is thrown away with
            // the set once the size is taken.
            $sources[ $index ][ substr( hash( 'sha256', $match[2] ), 0, 16 ) ] = true;
            $area = verifyum_activity_area( $host, $match[4] );
            $areas[ $area ][ $index ]++;
            if ( ( $area === 'page' or $area === 'proof' ) and !$is_internal and !$is_probe and !$is_crawler ){
                $key = $area === 'proof' ? '(a proof)' : $match[4];
                $paths[ $key ] = ( $paths[ $key ] ?? 0 ) + 1;
            }
        }
        fclose( $handle );
    }

    $reach = verifyum_activity_log_reach( $log_directory, $hosts );

    $distinct = [];
    foreach ( $sources as $bucket_sources ){
        $distinct[] = count( $bucket_sources );
    }

    arsort( $paths );
    $top = [];
    foreach ( array_slice( $paths, 0, VERIFYUM_ACTIVITY_TOP_PATHS, true ) as $key=>$hits ){
        $top[] = [ 'path'=>$key, 'requests'=>$hits ];
    }

    return [
        'requests'=>$requests,
        'distinct_sources'=>$distinct,
        'declared_bots'=>$declared_bots,
        'internal'=>$internal_requests,
        'probes'=>$probe_requests,
        'outside'=>$outside_requests,
        'areas'=>$areas,
        'top_paths'=>$top,
        'log_starts_at'=>$reach === null ? null : verifyum_service_iso_time( $reach ),
        'covers_whole_window'=>$reach !== null and $reach <= $from,
        'truncated'=>$truncated,
    ];
}
