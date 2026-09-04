<?php
declare( strict_types = 1 );

require_once dirname( __DIR__ ) .'/libs/func_verifyum.php';

$failures = [];
$checks = 0;

$check = function ( bool $condition, string $message ) use ( &$failures, &$checks ): void {
    $checks++;
    if ( $condition ){
        echo "  ok    {$message}\n";
    } else {
        $failures[] = $message;
    }
};

$nonce = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
$file_hash = str_repeat( '0123456789abcdef', 4 );
$manifest = [
    'file'=>[
        'hash'=>[ 'algorithm'=>'sha256', 'value'=>$file_hash ],
        'size'=>'1234',
    ],
    'nonce'=>$nonce,
    'protocol'=>'verifyum',
    'version'=>2,
];

$expected_jcs = '{"file":{"hash":{"algorithm":"sha256","value":"'. $file_hash .'"},"size":"1234"},"nonce":"'. $nonce .'","protocol":"verifyum","version":2}';
$expected_commitment = 'sha256:8412d6863b2328c6a7ff94d49ec087b18b6fc2db0b60da8b8dea97d30ac0612b';

$check( verifyum_jcs_encode( $manifest ) === $expected_jcs, 'PHP JCS matches the protocol vector' );
$check( verifyum_compute_commitment( $manifest ) === $expected_commitment, 'PHP commitment matches the JavaScript vector' );
$check( verifyum_normalize_commitment( $expected_commitment ) === $expected_commitment, 'valid commitment accepted' );
$check( verifyum_normalize_commitment( strtoupper( $expected_commitment ) ) === null, 'uppercase commitment rejected' );

$proof_ids = [];
for ( $index = 0; $index < 250; $index++ ){
    $proof_id = verifyum_generate_proof_id();
    $proof_ids[] = $proof_id;
    if ( !verifyum_valid_proof_id( $proof_id ) ){
        break;
    }
}
$check( count( $proof_ids ) === 250 and count( array_unique( $proof_ids ) ) === 250, '250 proof IDs are valid and unique' );

$proof_id = '0123456789abcdefghjkmnpqrs';
$memo = verifyum_build_memo( $proof_id, $expected_commitment );
$expected_memo = 'verifyum:v2:id='. $proof_id .';alg=sha256;commitment='. substr( $expected_commitment, 7 );
$check( $memo === $expected_memo, 'Memo matches the version 2 format' );
$check( strlen( $memo ) === 128, 'Memo byte length is fixed at 128 bytes' );
$check( !verifyum_valid_proof_id( '8'. substr( $proof_id, 1 ) ), 'non-canonical first proof ID character rejected' );
$check( !verifyum_valid_proof_id( substr( $proof_id, 0, 25 ) .'o' ), 'ambiguous Crockford letter rejected' );

$metadata_path = verifyum_metadata_path( '/var/lib/verifyum/proofs', $proof_id );
$check(
    $metadata_path === '/var/lib/verifyum/proofs/01/23/'. $proof_id .'.json',
    'metadata path uses the documented two-level shard'
);

echo "\n";
// R10 is verified with the client's own Ed25519 rather than a library's, so
// the standard's vectors are run against it. A signature that cannot be
// checked must never read as one that passed, which is what a bare install
// used to print: valid true and service_signature_valid null in the same
// object.
$client_path = dirname( __DIR__ ) .'/static/client-verifyum.py';
$client_source = (string)file_get_contents( $client_path );
$check(
    strlen( $client_source ) > 20000,
    'the client source is readable, so the checks below are about its contents'
);
$vectors = json_decode( trim( (string)shell_exec(
    'python '. escapeshellarg( __DIR__ .'/check-ed25519.py' )
    .' '. escapeshellarg( $client_path ) .' 2>&1'
) ), true );
$check(
    is_array( $vectors ) and ( $vectors['accepted'] ?? 0 ) === 3,
    'the built-in Ed25519 accepts all three RFC 8032 vectors'
);
$check(
    is_array( $vectors )
        and ( $vectors['tampered_rejected'] ?? 0 ) === 3
        and ( $vectors['short_key_rejected'] ?? 0 ) === 3
        and ( $vectors['short_signature_rejected'] ?? 0 ) === 3,
    'the built-in Ed25519 refuses a tampered message, a short key and a short signature'
);
$check(
    $client_source !== '' and !str_contains( $client_source, 'if _Ed25519PublicKey is None:' ),
    'the signature check no longer reports unchecked when cryptography is absent'
);
$check(
    str_contains( $client_source, 'A check that did not run is not a check that passed.' ),
    'the command refuses to call a proof witnessed while a check was skipped'
);

// A receipt has to stand without us. The claim is not convenience: it is
// that if this service is gone in seven years, the file, the receipt and a
// SHA-256 implementation still settle the question. The check runs with
// every outbound call rigged to raise, so a pass cannot come from being
// online.
$offline = json_decode( trim( (string)shell_exec(
    'python '. escapeshellarg( __DIR__ .'/check-offline.py' )
    .' '. escapeshellarg( dirname( __DIR__ ) .'/static/client-verifyum.py' )
    .' '. escapeshellarg( __DIR__ .'/fixtures/self-bearing-receipt.json' ) .' 2>&1'
) ), true );
$check(
    is_array( $offline ) and ( $offline['ran_without_network'] ?? false ) === true,
    'a complete receipt verifies with every network call rigged to fail'
);
$check(
    is_array( $offline ) and ( $offline['witness_half_passes'] ?? false ) === true,
    'the Merkle path, checkpoint hash and service signature all check from the receipt alone'
);
$check(
    is_array( $offline ) and ( $offline['wrong_file_rejected'] ?? false ) === true,
    'offline verification refuses a file that is not the one the receipt binds'
);
$check(
    is_array( $offline ) and ( $offline['thin_receipt_refused'] ?? false ) === true,
    'a receipt written before its checkpoint existed says so instead of checking less'
);
$check(
    is_array( $offline ) and ( $offline['memo_rebuilds'] ?? false ) === true
        and ( $offline['memo_is_128_bytes'] ?? false ) === true,
    'the anchor memo rebuilds from the receipt at the fixed 128 bytes'
);

if ( $failures === [] ){
    echo "check-protocol: {$checks} checks passed\n";
    exit( 0 );
}

foreach ( $failures as $failure ){
    fwrite( STDERR, "  FAIL  {$failure}\n" );
}
fwrite( STDERR, "\ncheck-protocol: ". count( $failures ) ." of {$checks} checks failed\n" );
exit( 1 );
