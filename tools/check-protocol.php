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
if ( $failures === [] ){
    echo "check-protocol: {$checks} checks passed\n";
    exit( 0 );
}

foreach ( $failures as $failure ){
    fwrite( STDERR, "  FAIL  {$failure}\n" );
}
fwrite( STDERR, "\ncheck-protocol: ". count( $failures ) ." of {$checks} checks failed\n" );
exit( 1 );
