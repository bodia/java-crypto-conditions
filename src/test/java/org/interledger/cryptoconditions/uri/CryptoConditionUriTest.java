package org.interledger.cryptoconditions.uri;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.interledger.cryptoconditions.CompoundCondition;
import org.interledger.cryptoconditions.Condition;
import org.interledger.cryptoconditions.ConditionType;
import org.interledger.cryptoconditions.HexDump;
import org.interledger.cryptoconditions.types.CryptoConditionUri;
import org.junit.Test;

import java.net.URI;
import java.util.EnumSet;

/**
 * JUnit tests to exercise the {@link CryptoConditionUri} class. Directly translated from
 * five-bells-condition tests
 */
public class CryptoConditionUriTest {

  @Test
  public void test_parse_preimage_sha_256() throws UriEncodingException {
    URI uri = URI.create(
        "ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?cost=0&fpt=preimage-sha-256");

    Condition condition = CryptoConditionUri.parse(uri);

    assertEquals(ConditionType.PREIMAGE_SHA256, condition.getType());
    assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        HexDump.toHexString(condition.getFingerprint()));
    assertEquals(0, condition.getCost());
  }

  @Test
  public void test_parse_prefix_sha_256() throws UriEncodingException {
    URI uri = URI.create(
        "ni:///sha-256;47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU?cost=0&fpt=prefix-sha-256"
        + "&subtypes=preimage-sha-256,prefix-sha-256");

    Condition condition = CryptoConditionUri.parse(uri);

    assertEquals(ConditionType.PREFIX_SHA256, condition.getType());
    assertEquals("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
        HexDump.toHexString(condition.getFingerprint()));
    assertEquals(0, condition.getCost());

    assertTrue(condition instanceof CompoundCondition);
    CompoundCondition compoundCondition = (CompoundCondition) condition;
    assertEquals(EnumSet.of(ConditionType.PREIMAGE_SHA256, ConditionType.PREFIX_SHA256),
        compoundCondition.getSubtypes());
  }
}
