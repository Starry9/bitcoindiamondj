package org.bitcoinj.examples;

import org.bitcoinj.core.*;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.params.RegTestParams;
import org.bitcoinj.script.*;

public class ExampleBCDTransaction {

    private static void signInputsOfTransaction(Address sourceAddress, Transaction tx, ECKey key) {
        for (int i = 0; i < tx.getInputs().size(); i++) {
            Script scriptPubKey = ScriptBuilder.createOutputScript(sourceAddress);
            Sha256Hash hash = tx.hashForSignature(i, scriptPubKey, Transaction.SigHash.ALL, true);
            ECKey.ECDSASignature ecdsaSignature = key.sign(hash);
            TransactionSignature txSignature = new TransactionSignature(ecdsaSignature, Transaction.SigHash.ALL, true);

            if (ScriptPattern.isP2PK(scriptPubKey)) {
                tx.getInput(i).setScriptSig(ScriptBuilder.createInputScript(txSignature));
            } else {
                if (!ScriptPattern.isP2PKH(scriptPubKey)) {
                    throw new ScriptException(ScriptError.SCRIPT_ERR_UNKNOWN_ERROR, "Unable to sign this scrptPubKey: " + scriptPubKey);
                }
                tx.getInput(i).setScriptSig(ScriptBuilder.createInputScript(txSignature, key));
            }
        }
    }


    public static void main(String[] args) {
        NetworkParameters params = RegTestParams.get();

        String prv = "cVomyUXYSBkxQ78Fq1bjFrWeVyzHxJTDdeCQbJyHWyGRzTuCAkSf";
        DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(params, prv);
//        BigInteger privKey = Base58.decodeToBigInteger(prv);
//        ECKey key = new ECKey();
//        ECKey key = ECKey.fromPrivate(privKey);
//        ECKey key = ECKey.fromPrivate(prv.getBytes());
        ECKey key = dumpedPrivateKey.getKey();
        String privateKey = key.getPrivateKeyAsWiF(params);

        System.out.println("privateKey" + privateKey);

        Address address = Address.fromKey(params, key, Script.ScriptType.P2PKH);
        System.out.println("address " + address);
        assert (address.toString().equals("muMTc1XG7ZMTFZ2tcMEZVw2p6gxME9gbHf"));
        String txid = "e8b8dc574f0c7e443e1cef48f910be9153625ebe6d451cfc583ef44aca664080";
        long index = 1;
        String toAddr = "mon7weVrGGduAgCuo4gTGndDDX23Jojuh1";

        Address addr = Address.fromString(params, toAddr);
        long toAmount = 999999000;
        Transaction tx = new Transaction(params, true);
        tx.addOutput(Coin.valueOf(toAmount), addr);
        Script script = ScriptBuilder.createOutputScript(address);
        tx.addInput(Sha256Hash.wrap(txid), index, script);
        System.out.println("tx " + tx);
        signInputsOfTransaction(address, tx, key);
        tx.verify();
        System.out.println("fee " + tx.getFee());
        System.out.println("tx hex " + Utils.HEX.encode(tx.bitcoinSerialize()));
    }
}
