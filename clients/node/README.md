# verifyum

Prove that a file existed, unchanged, at a point in time. The file never
leaves your machine: only a domain-separated commitment is sent.

**Four independent records, none of them ours.** Every proof is folded into
an hourly Merkle checkpoint, and each checkpoint is witnessed by

- **OpenTimestamps into Bitcoin**, whose durability is a property of the
  protocol: every full node holds every block;
- a **qualified electronic timestamp under eIDAS Article 41(2)**, issued by
  Sectigo (Europe) SL, whose qualified service is granted on Spain's EU
  Trusted List, so the timestamp carries a legal presumption of accuracy
  across the Union;
- **Sigsum**, cosigned by witnesses run by Glasklar, Mullvad and Tillitis;
- **Certificate Transparency**, one certificate per daily checkpoint whose
  hostname encodes the checkpoint root.

Four further records are the operator's own and are labelled as such, never
counted as independent. A Solana Mainnet memo carries the commitment and
gives finality in seconds; it is the fast confirmation, not the durable one.

The eIDAS presumption covers the checkpoint root, not the contents of your
file. All of it is spelled out at https://verifyum.com/witness

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
