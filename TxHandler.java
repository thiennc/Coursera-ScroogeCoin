import java.util.ArrayList;

public class TxHandler {

    /**
     * Creates a public ledger whose current UTXOPool (collection of unspent transaction outputs) is
     * {@code utxoPool}. This should make a copy of utxoPool by using the UTXOPool(UTXOPool uPool)
     * constructor.
     */
    private UTXOPool _utxoPool;

    public TxHandler(UTXOPool utxoPool) {
        _utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * @return true if:
     * (1) all outputs claimed by {@code tx} are in the current UTXO pool, 
     * (2) the signatures on each input of {@code tx} are valid, 
     * (3) no UTXO is claimed multiple times by {@code tx},
     * (4) all of {@code tx}s output values are non-negative, and
     * (5) the sum of {@code tx}s input values is greater than or equal to the sum of its output
     *     values; and false otherwise.
     */
    public boolean isValidTx(Transaction tx) {
        double sumInput = 0;
        double sumOutput = 0;
        ArrayList<UTXO> usedUTXO = new ArrayList<>();

        for (int i=0;i<tx.numInputs();i++) {
            Transaction.Input input = tx.getInput(i);
            int outputIndex = input.outputIndex;
            byte[] prevTxHash = input.prevTxHash;
            byte[] signature = input.signature;

            UTXO utxo = new UTXO(prevTxHash, outputIndex);

            //check rule (1): all outputs claimed by tx are in current UTXO pool
            if (!_utxoPool.contains(utxo)) {
                return false;
            }
            //check rule (2): the signatures on each input of tx are valid
            Transaction.Output output = _utxoPool.getTxOutput(utxo);
            byte[] message = tx.getRawDataToSign(i);
            if (!Crypto.verifySignature(output.address,message,signature)) {
                return false;
            }
            //check rule (3): no UTXO is claimed multiple times by tx
            if (usedUTXO.contains(utxo)) {
                return false;
            }
            usedUTXO.add(utxo);
            sumInput += output.value;
        }
        //check rule (4): all of tx output values are non-negative
        for (int i=0;i<tx.numOutputs();i++) {
            Transaction.Output output = tx.getOutput(i);
            if (output.value < 0) {
                return false;
            }
            sumOutput += output.value;
        }
        //check rule (5): the sum of tx input values is greater than or equal to the sum of its output values
        if (sumInput < sumOutput) {
            return false;
        }
        return true;
    }

    /**
     * Handles each epoch by receiving an unordered array of proposed transactions, checking each
     * transaction for correctness, returning a mutually valid array of accepted transactions, and
     * updating the current UTXO pool as appropriate.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        ArrayList<Transaction> validTxs = new ArrayList<>();
        for (Transaction t : possibleTxs) {
            if (isValidTx(t)) {
                validTxs.add(t);

                //remove utxo
                for (Transaction.Input input : t.getInputs()) {
                    int outputIndex = input.outputIndex;
                    byte[] prevTxHash = input.prevTxHash;
                    UTXO utxo = new UTXO(prevTxHash, outputIndex);
                    _utxoPool.removeUTXO(utxo);
                }
                //add new utxo
                byte[] hash = t.getHash();
                for (int i=0;i<t.numOutputs();i++) {
                    UTXO utxo = new UTXO(hash, i);
                    _utxoPool.addUTXO(utxo, t.getOutput(i));
                }
            }
        }
        Transaction[] validTxsArr = new Transaction[validTxs.size()];
        validTxsArr = validTxs.toArray(validTxsArr);
        return validTxsArr;
    }

}
