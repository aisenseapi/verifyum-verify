# verifyum

Prove that a file existed, unchanged, at a point in time. The file never
leaves your machine: only a domain-separated commitment is sent.

    npx verifyum stamp contract.pdf
    npx verifyum verify contract.pdf

`stamp` writes `contract.pdf.verifyum.json` beside the file. That receipt
holds the nonce, which is the only thing tying your file to its public
proof, and which Verifyum never has. Losing it loses the link for good.

Treat it like a key. The file is created with mode 0600, which POSIX honours
and Windows ignores, so writing it does not make it private: do not commit
it and do not sync it anywhere you would not put a credential.

`verify` recomputes the commitment from the bytes and the receipt and checks
it against the public record. `verifyum witness contract.pdf` additionally
walks the Merkle path to the checkpoint and checks the service signature.

Exit codes: 0 all good, 1 a check failed, 2 usage or file error, 3 the
service was unavailable, which is worth retrying.

It also works as a library:

    import { anchorFile, verify, verifyWitness } from "verifyum";

No dependencies, Node 20 or later. The protocol, the witness layer and
independent verifiers in six languages are at
https://github.com/aisenseapi/verifyum-verify

It proves the bytes existed and have not changed. It does not prove
authorship, ownership, or that anything in the file is true.

MIT.
