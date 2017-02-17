package org.interledger.cryptoconditions;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.Charset;

import org.junit.Test;

import org.interledger.cryptoconditions.encoding.FulfillmentInputStream;
import org.interledger.cryptoconditions.encoding.OerDecodingException;
import org.interledger.cryptoconditions.types.*;

import net.i2p.crypto.eddsa.Utils;
// TODO:(0) Complete tests
public class TestEd25519Fulfillment {

    static {
        Ed25519Fulfillment.UserHasReadEd25519JavaDisclaimerAndIsAwareOfSecurityIssues();
    }
    final byte[] TEST_SEED = Utils.hexToBytes("0000000000000000000000000000000000000000000000000000000000000000");

    static final byte[] TEST_MSG = "Hello World! Conditions are here!".getBytes(Charset.forName("UTF-8"));

    static final byte[] TEST_KO_MSG = "This is a wrong secret message".getBytes(Charset.forName("UTF-8"));

    static final String FF_OK_URI = "cf:4:7Bcrk61eVjv0kyxw4SRQNMNUZ-8u_U1k6_gZaDRn4r-2IpH62UMvjymLnEpIldvik_b_2hpo2t8Mze9fR6DHISpf6jzal6P0wD6p8uisHOyGpR1FISer26CdG28zHAcK"; 


    @Test
    public void testEd25519Fulfillment() throws IOException, UnsupportedConditionException, OerDecodingException {
        // Build from URI
        Fulfillment ff_ok = FulfillmentFactory.getFulfillmentFromURI(FF_OK_URI);
        assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

        // Build from secret
        ff_ok = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_MSG));
        ff_ok.getCondition();
        assertTrue("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

        ff_ok = Ed25519Fulfillment.BuildFromSecrets(new KeyPayload(TEST_SEED), new MessagePayload(TEST_KO_MSG));
        ff_ok.getCondition();
        assertFalse("Fulfillment validates TEST_MSG", ff_ok.validate(new MessagePayload(TEST_MSG)));

    }

}
